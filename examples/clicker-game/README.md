# OVP Clicker — Anti-Cheat Demo

A browser clicker game demonstrating the **Optimistic Verification Protocol (OVP)** for anti-cheat enforcement. The server re-executes every game action using a canonical Rust step function compiled to WASM, and generates cryptographic fraud proofs when tampering is detected.

## What This Demo Shows

1. **Deterministic state transitions** — Game logic is defined once in Rust; the JS client mirrors it exactly
2. **Server-side re-execution** — Every action batch is verified by re-executing the canonical step function
3. **OVP fraud proofs** — On mismatch, the server builds a Merkle commitment over transitions and generates a fraud proof with `generate_fraud_proof()`
4. **Instant detection** — CheatEngine-style memory edits (e.g. `gameState.gold = 999999n`) are caught on the next batch

## Protocol Flow

```
Client                          Server
  │                               │
  │◄──── welcome (initial_state) ─┤
  │                               │
  │  click, click, click...       │
  │  (records transitions)        │
  │                               │
  │── batch (5 transitions) ─────►│
  │                               │  re-execute each step
  │                               │  game_step(prev, action) == claimed?
  │◄──── batch_ok ────────────────┤  ✓ all match
  │                               │
  │  * player cheats in console * │
  │  gameState.gold = 999999n     │
  │                               │
  │── batch (transitions) ───────►│
  │                               │  game_step(prev, action) ≠ claimed!
  │                               │  build OVP commitment + fraud proof
  │◄──── kick (fraud_proof) ──────┤
  │                               │  close connection
  │  ┌────────────────────┐       │
  │  │ CHEATING DETECTED  │       │
  │  │ [fraud proof JSON] │       │
  │  └────────────────────┘       │
```

## Prerequisites

- **Rust** (stable toolchain)
- **wasm-pack** — `cargo install wasm-pack`
- **Node.js** >= 16

## Build & Run

```bash
# 1. Build the WASM verifier
cd examples/clicker-game/wasm-verifier
wasm-pack build --target nodejs --out-dir ../server/pkg

# 2. Install server dependencies and start
cd ../server
npm install
node server.js
```

Open **http://localhost:3000** in your browser.

## How to Simulate Cheating

While playing, open the browser console (F12) and run:

```js
// Give yourself 999999 gold
gameState.gold = 999999n;
updateUI();
```

Then click once. The next batch will contain a transition where your `prev_state` has `gold = 999999` but the server's state has the legitimate value. The server detects the mismatch, generates an OVP fraud proof, and kicks you with a full-screen overlay showing the cryptographic evidence.

## Game Design

| Field | Size | Description |
|-------|------|-------------|
| `gold` | u64 LE | Currency earned by clicking |
| `click_power` | u64 LE | Gold earned per click |
| `upgrade_level_0` | u64 LE | "Better Pickaxe" level (+1 click power) |
| `upgrade_level_1` | u64 LE | "Gold Rush" level (2x click power) |

**Actions**: Click (gold += click_power), BuyUpgrade(0) (cost 10*2^level), BuyUpgrade(1) (cost 50*2^level)

## Files

```
wasm-verifier/
  Cargo.toml          # cdylib crate depending on ovp + wasm-bindgen
  src/lib.rs          # GameState, Action, step function, WASM exports, OVP integration
server/
  package.json        # ws dependency
  server.js           # HTTP + WebSocket server with WASM verification
public/
  index.html          # Game UI + kick overlay
  game.js             # Client-side game logic + WebSocket batch protocol
```
