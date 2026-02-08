// ---------------------------------------------------------------------------
// OVP Clicker — Node.js server (HTTP static + WebSocket verification)
// ---------------------------------------------------------------------------

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

// Load WASM verifier
let wasm;
try {
  wasm = require('./pkg/clicker_verifier.js');
} catch (e) {
  console.error('Failed to load WASM verifier.');
  console.error('Build it first: cd ../wasm-verifier && wasm-pack build --target nodejs --out-dir ../server/pkg');
  process.exit(1);
}

const PORT = parseInt(process.env.PORT, 10) || 3000;
const PUBLIC_DIR = path.join(__dirname, '..', 'public');

// ---------------------------------------------------------------------------
// MIME types for static file serving
// ---------------------------------------------------------------------------

const MIME = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

// ---------------------------------------------------------------------------
// HTTP static file server
// ---------------------------------------------------------------------------

const server = http.createServer((req, res) => {
  let filePath = path.join(PUBLIC_DIR, req.url === '/' ? 'index.html' : req.url);
  filePath = path.normalize(filePath);

  // Prevent path traversal
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  const ext = path.extname(filePath);
  const contentType = MIME[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404);
      res.end('Not found');
      return;
    }
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(data);
  });
});

// ---------------------------------------------------------------------------
// Hex utilities
// ---------------------------------------------------------------------------

function toHex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

function fromHex(hex) {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

// ---------------------------------------------------------------------------
// WebSocket server
// ---------------------------------------------------------------------------

const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', (req, socket, head) => {
  wss.handleUpgrade(req, socket, head, (ws) => {
    wss.emit('connection', ws, req);
  });
});

const sessions = new Map();

wss.on('connection', (ws) => {
  const sessionId = crypto.randomUUID();
  const initialState = wasm.initial_state();

  const session = {
    id: sessionId,
    serverState: new Uint8Array(initialState),
    transitionCount: 0,
    kicked: false,
    batchQueue: [],
    processing: false,
  };
  sessions.set(sessionId, session);

  console.log(`[${sessionId.substring(0, 8)}] Connected`);

  ws.send(JSON.stringify({
    type: 'welcome',
    session_id: sessionId,
    initial_state: toHex(initialState),
  }));

  ws.on('message', (data) => {
    if (session.kicked) return;

    let msg;
    try {
      msg = JSON.parse(data.toString());
    } catch {
      ws.send(JSON.stringify({ type: 'error', message: 'Invalid JSON' }));
      return;
    }

    if (msg.type === 'batch') {
      handleBatch(ws, session, msg);
    }
  });

  ws.on('close', () => {
    console.log(`[${session.id.substring(0, 8)}] Disconnected (verified ${session.transitionCount} transitions)`);
    sessions.delete(sessionId);
  });
});

// ---------------------------------------------------------------------------
// Batch verification (async — client keeps playing, server responds when done)
// ---------------------------------------------------------------------------

function handleBatch(ws, session, msg) {
  if (!Array.isArray(msg.transitions) || msg.transitions.length === 0) {
    ws.send(JSON.stringify({ type: 'error', message: 'Empty batch' }));
    return;
  }

  // Enqueue batch for sequential processing via setImmediate so the event
  // loop stays responsive and the client can keep sending actions.
  session.batchQueue.push({ ws, transitions: msg.transitions });
  if (!session.processing) {
    processNextBatch(session);
  }
}

function processNextBatch(session) {
  if (session.batchQueue.length === 0 || session.kicked) {
    session.processing = false;
    return;
  }

  session.processing = true;
  const { ws, transitions } = session.batchQueue.shift();

  setImmediate(() => {
    verifyBatch(ws, session, transitions);
    processNextBatch(session);
  });
}

function verifyBatch(ws, session, transitions) {
  if (session.kicked) return;

  for (let i = 0; i < transitions.length; i++) {
    const t = transitions[i];

    if (!t.prev_state || !t.action || !t.claimed_state) {
      trySend(ws, { type: 'error', message: `Transition ${i}: missing fields` });
      return;
    }

    // Check that client's prev_state matches server's tracked state.
    // A mismatch means the client tampered with state between transitions.
    const serverHex = toHex(session.serverState);
    if (t.prev_state !== serverHex) {
      kickForDesync(ws, session, t, serverHex);
      return;
    }

    // Re-execute the canonical step function
    const actionBytes = fromHex(t.action);
    const computed = wasm.game_step(session.serverState, actionBytes);
    const claimedBytes = fromHex(t.claimed_state);

    if (toHex(computed) !== toHex(claimedBytes)) {
      kickForStepMismatch(ws, session, transitions);
      return;
    }

    // Advance server state
    session.serverState = new Uint8Array(computed);
    session.transitionCount++;
  }

  trySend(ws, {
    type: 'batch_ok',
    verified_count: transitions.length,
    total_verified: session.transitionCount,
  });
}

// Client's prev_state doesn't match server — they modified state outside the
// step function (e.g. gameState.gold = 999999n in console). Build an OVP proof
// by constructing a transition from the server's real state.
function kickForDesync(ws, session, transition, serverHex) {
  console.log(`[${session.id.substring(0, 8)}] FRAUD DETECTED — state desync`);

  // Build a proof transition: server's prev_state + client's action → server's
  // computed result vs client's claimed_state
  const proofBatch = JSON.stringify({ transitions: [{
    prev_state: serverHex,
    action: transition.action,
    claimed_state: transition.claimed_state,
  }]});

  const resultJson = wasm.verify_batch(proofBatch);
  const result = JSON.parse(resultJson);

  session.kicked = true;

  const detail = result.detail ||
    `State tampered: server expected ${serverHex.substring(0, 16)}..., ` +
    `client sent ${transition.prev_state.substring(0, 16)}...`;

  console.log(`[${session.id.substring(0, 8)}] Kicking player: ${detail}`);

  trySend(ws, {
    type: 'kick',
    reason: 'State tampering detected — OVP fraud proof generated',
    detail,
    fraud_proof: result.fraud_proof || null,
  });

  ws.close(1008, 'Cheating detected');
}

// Client's step function produced a different result — they modified the step
// function itself or injected a bad claimed_state.
function kickForStepMismatch(ws, session, transitions) {
  console.log(`[${session.id.substring(0, 8)}] FRAUD DETECTED — step mismatch`);

  const batchJson = JSON.stringify({ transitions });
  const resultJson = wasm.verify_batch(batchJson);
  const result = JSON.parse(resultJson);

  session.kicked = true;

  const detail = result.detail || 'Step function output mismatch';
  console.log(`[${session.id.substring(0, 8)}] Kicking player: ${detail}`);

  trySend(ws, {
    type: 'kick',
    reason: 'State tampering detected — OVP fraud proof generated',
    detail,
    fraud_proof: result.fraud_proof || null,
  });

  ws.close(1008, 'Cheating detected');
}

function trySend(ws, msg) {
  if (ws.readyState === ws.OPEN) {
    ws.send(JSON.stringify(msg));
  }
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

server.listen(PORT, () => {
  console.log(`OVP Clicker server running on http://localhost:${PORT}`);
  console.log(`Serving static files from ${PUBLIC_DIR}`);
});
