// ---------------------------------------------------------------------------
// OVP Clicker — Client-side game logic + WebSocket batch verification
// ---------------------------------------------------------------------------

const STATE_SIZE = 32;
const ACTION_SIZE = 9;
const BATCH_SIZE = 5;
const BATCH_INTERVAL_MS = 2000;
const MAX_UPGRADE_LEVEL = 62n;

// ---------------------------------------------------------------------------
// GameState — mirrors the Rust struct exactly (LE binary)
// ---------------------------------------------------------------------------

class GameState {
  constructor(gold = 0n, clickPower = 1n, upgradeLevel0 = 0n, upgradeLevel1 = 0n) {
    this.gold = BigInt(gold);
    this.clickPower = BigInt(clickPower);
    this.upgradeLevel0 = BigInt(upgradeLevel0);
    this.upgradeLevel1 = BigInt(upgradeLevel1);
  }

  toBytes() {
    const buf = new ArrayBuffer(STATE_SIZE);
    const view = new DataView(buf);
    view.setBigUint64(0, this.gold, true);
    view.setBigUint64(8, this.clickPower, true);
    view.setBigUint64(16, this.upgradeLevel0, true);
    view.setBigUint64(24, this.upgradeLevel1, true);
    return new Uint8Array(buf);
  }

  static fromBytes(bytes) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    return new GameState(
      view.getBigUint64(0, true),
      view.getBigUint64(8, true),
      view.getBigUint64(16, true),
      view.getBigUint64(24, true),
    );
  }

  clone() {
    return new GameState(this.gold, this.clickPower, this.upgradeLevel0, this.upgradeLevel1);
  }

  upgradeCost(id) {
    if (id === 0) return 10n * (1n << this.upgradeLevel0);
    if (id === 1) return 50n * (1n << this.upgradeLevel1);
    return 0n;
  }
}

// ---------------------------------------------------------------------------
// Action encoding
// ---------------------------------------------------------------------------

function encodeClick() {
  const buf = new Uint8Array(ACTION_SIZE);
  buf[0] = 0x00;
  return buf;
}

function encodeBuyUpgrade(id) {
  const buf = new ArrayBuffer(ACTION_SIZE);
  const view = new DataView(buf);
  view.setUint8(0, 0x01);
  view.setBigUint64(1, BigInt(id), true);
  return new Uint8Array(buf);
}

// ---------------------------------------------------------------------------
// Deterministic step function (must match Rust exactly)
// ---------------------------------------------------------------------------

function applyAction(state, actionBytes) {
  const next = state.clone();
  const type_ = actionBytes[0];

  if (type_ === 0x00) {
    // Click
    next.gold = saturatingAdd(next.gold, next.clickPower);
  } else if (type_ === 0x01) {
    const view = new DataView(actionBytes.buffer, actionBytes.byteOffset, actionBytes.byteLength);
    const id = view.getBigUint64(1, true);

    if (id === 0n) {
      if (next.upgradeLevel0 >= MAX_UPGRADE_LEVEL) return next;
      const cost = 10n * (1n << next.upgradeLevel0);
      if (next.gold >= cost) {
        next.gold -= cost;
        next.clickPower = saturatingAdd(next.clickPower, 1n);
        next.upgradeLevel0 += 1n;
      }
    } else if (id === 1n) {
      if (next.upgradeLevel1 >= MAX_UPGRADE_LEVEL) return next;
      const cost = 50n * (1n << next.upgradeLevel1);
      if (next.gold >= cost) {
        next.gold -= cost;
        next.clickPower = saturatingMul(next.clickPower, 2n);
        next.upgradeLevel1 += 1n;
      }
    }
  }
  return next;
}

function saturatingAdd(a, b) {
  const max = 0xFFFFFFFFFFFFFFFFn;
  const sum = a + b;
  return sum > max ? max : sum;
}

function saturatingMul(a, b) {
  const max = 0xFFFFFFFFFFFFFFFFn;
  if (a === 0n || b === 0n) return 0n;
  const product = a * b;
  return product > max ? max : product;
}

// ---------------------------------------------------------------------------
// Hex utilities
// ---------------------------------------------------------------------------

function toHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// Game instance
// ---------------------------------------------------------------------------

let gameState = new GameState();
let transitionBuffer = [];
let totalVerified = 0;
let ws = null;
let sessionId = null;
let kicked = false;
let batchTimer = null;

// ---------------------------------------------------------------------------
// UI references
// ---------------------------------------------------------------------------

const $gold = document.getElementById('goldAmount');
const $power = document.getElementById('clickPower');
const $clickBtn = document.getElementById('clickBtn');
const $upgrade0 = document.getElementById('upgrade0');
const $upgrade1 = document.getElementById('upgrade1');
const $cost0 = document.getElementById('cost0');
const $cost1 = document.getElementById('cost1');
const $level0 = document.getElementById('level0');
const $level1 = document.getElementById('level1');
const $statusDot = document.getElementById('statusDot');
const $statusText = document.getElementById('statusText');
const $verifiedCount = document.getElementById('verifiedCount');
const $logBox = document.getElementById('logBox');
const $kickOverlay = document.getElementById('kickOverlay');
const $kickReason = document.getElementById('kickReason');
const $kickDetail = document.getElementById('kickDetail');
const $proofToggle = document.getElementById('proofToggle');
const $proofPanel = document.getElementById('proofPanel');
const $playAgainBtn = document.getElementById('playAgainBtn');

// ---------------------------------------------------------------------------
// UI updates
// ---------------------------------------------------------------------------

function updateUI() {
  $gold.textContent = gameState.gold.toLocaleString();
  $power.textContent = gameState.clickPower.toLocaleString();
  $cost0.textContent = `Cost: ${gameState.upgradeCost(0).toLocaleString()} gold`;
  $cost1.textContent = `Cost: ${gameState.upgradeCost(1).toLocaleString()} gold`;
  $level0.textContent = `Level ${gameState.upgradeLevel0}`;
  $level1.textContent = `Level ${gameState.upgradeLevel1}`;

  $upgrade0.disabled = kicked || !ws || gameState.gold < gameState.upgradeCost(0) || gameState.upgradeLevel0 >= MAX_UPGRADE_LEVEL;
  $upgrade1.disabled = kicked || !ws || gameState.gold < gameState.upgradeCost(1) || gameState.upgradeLevel1 >= MAX_UPGRADE_LEVEL;
  $clickBtn.disabled = kicked || !ws;
}

function log(msg, cls) {
  const line = document.createElement('div');
  if (cls) line.className = cls;
  line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
  $logBox.appendChild(line);
  $logBox.scrollTop = $logBox.scrollHeight;
}

function setStatus(state, text) {
  $statusDot.className = 'status-dot ' + state;
  $statusText.textContent = text;
}

// ---------------------------------------------------------------------------
// Game actions
// ---------------------------------------------------------------------------

function setGameState(s) {
  gameState = s;
  window.gameState = s;
}

function doAction(actionBytes) {
  if (kicked || !ws) return;

  const prevState = gameState.toBytes();
  setGameState(applyAction(gameState, actionBytes));
  const claimedState = gameState.toBytes();

  transitionBuffer.push({
    prev_state: toHex(prevState),
    action: toHex(actionBytes),
    claimed_state: toHex(claimedState),
  });

  updateUI();

  if (transitionBuffer.length >= BATCH_SIZE) {
    flushBatch();
  }
}

$clickBtn.addEventListener('click', () => doAction(encodeClick()));
$upgrade0.addEventListener('click', () => doAction(encodeBuyUpgrade(0)));
$upgrade1.addEventListener('click', () => doAction(encodeBuyUpgrade(1)));

// ---------------------------------------------------------------------------
// Batch sending
// ---------------------------------------------------------------------------

function flushBatch() {
  if (transitionBuffer.length === 0 || !ws || kicked) return;

  const batch = transitionBuffer.splice(0);
  ws.send(JSON.stringify({ type: 'batch', transitions: batch }));
  log(`Sent batch of ${batch.length} transitions`);
}

function startBatchTimer() {
  if (batchTimer) clearInterval(batchTimer);
  batchTimer = setInterval(() => flushBatch(), BATCH_INTERVAL_MS);
}

// ---------------------------------------------------------------------------
// WebSocket connection
// ---------------------------------------------------------------------------

function connect() {
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${protocol}//${location.host}`);

  ws.addEventListener('open', () => {
    setStatus('connected', 'Connected');
    log('Connected to server');
    startBatchTimer();
    updateUI();
  });

  ws.addEventListener('message', (event) => {
    const msg = JSON.parse(event.data);

    if (msg.type === 'welcome') {
      sessionId = msg.session_id;
      setGameState(GameState.fromBytes(fromHex(msg.initial_state)));
      totalVerified = 0;
      transitionBuffer = [];
      log(`Session ${sessionId.substring(0, 8)}... started`);
      updateUI();
    } else if (msg.type === 'batch_ok') {
      totalVerified = msg.total_verified;
      $verifiedCount.textContent = `Verified: ${totalVerified}`;
      log(`Batch OK (${msg.verified_count} verified, ${totalVerified} total)`);
    } else if (msg.type === 'kick') {
      handleKick(msg);
    } else if (msg.type === 'error') {
      log(`Server error: ${msg.message}`, 'error');
    }
  });

  ws.addEventListener('close', () => {
    setStatus('disconnected', 'Disconnected');
    if (!kicked) log('Disconnected from server', 'warn');
    ws = null;
    updateUI();
    if (!kicked) {
      log('Reconnecting in 2s...', 'warn');
      setTimeout(connect, 2000);
    }
  });

  ws.addEventListener('error', () => {
    log('WebSocket error', 'error');
  });
}

// ---------------------------------------------------------------------------
// Kick handling
// ---------------------------------------------------------------------------

function handleKick(msg) {
  kicked = true;
  if (batchTimer) clearInterval(batchTimer);
  log(`KICKED: ${msg.reason}`, 'error');

  $kickReason.textContent = msg.reason || 'State tampering detected';
  $kickDetail.textContent = msg.detail || '';

  if (msg.fraud_proof) {
    $proofPanel.textContent = JSON.stringify(msg.fraud_proof, null, 2);
  } else {
    $proofPanel.textContent = 'No cryptographic proof available';
  }

  $kickOverlay.classList.add('visible');
  updateUI();
}

$proofToggle.addEventListener('click', () => {
  $proofPanel.classList.toggle('visible');
  $proofToggle.textContent = $proofPanel.classList.contains('visible')
    ? 'Hide Cryptographic Proof'
    : 'Show Cryptographic Proof';
});

$playAgainBtn.addEventListener('click', () => {
  kicked = false;
  $kickOverlay.classList.remove('visible');
  $proofPanel.classList.remove('visible');
  connect();
});

// ---------------------------------------------------------------------------
// Expose for cheat testing (open console, modify gameState, call updateUI)
// ---------------------------------------------------------------------------

window.gameState = gameState;
window.GameState = GameState;

// Override updateUI so console cheats (e.g. gameState.gold = 999999n; updateUI())
// are adopted. During normal play, setGameState keeps window.gameState in sync
// so this check is a no-op.
const origUpdateUI = updateUI;
window.updateUI = function() {
  if (window.gameState !== gameState) {
    gameState = window.gameState;
  }
  origUpdateUI();
};

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

setStatus('connecting', 'Connecting...');
connect();
