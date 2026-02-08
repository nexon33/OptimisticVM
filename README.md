# Optimistic Verification Protocol (OVP)

Rust implementation of the [OVP Core Specification v0.1](spec.md) — a protocol for verifying arbitrary deterministic computations without re-executing them.

OVP combines Merkle commitments, interactive bisection disputes, and zero-knowledge proof escalation to make cheating economically irrational. It is designed to be language-agnostic, domain-agnostic, and settlement-agnostic.

**Use cases**: AI inference verification, gaming anti-cheat, media authenticity, serverless function verification — any computation that can be deterministically executed.

## Status

This crate implements the **full verification path** (re-execution based). The optimistic sampling path (random checkpoint sampling via PRNG) is not yet implemented.

| Component | Status |
|-----------|--------|
| Core data types + canonical serialization | Done |
| Hash functions with domain separation | Done |
| Hash chain construction | Done |
| Merkle tree (build, prove, verify) | Done |
| Commitment protocol (create, sign, verify) | Done |
| Transition verification (full re-execution) | Done |
| Fraud proof generation + validation | Done |
| Bisection dispute protocol | Done |
| ZK escalation (Mock proof type) | Done |
| Code integrity (Snitch Protocol) | Done |
| Challenge-response sampling (LCG PRNG) | Not yet |
| Economic security model | Not yet |
| Production ZK proof types | Not yet |

## Quick Start

```toml
# Cargo.toml
[dependencies]
ovp = { path = "." }
```

```rust
use ovp::commitment::{create_commitment, sign_commitment, verify_signed_commitment};
use ovp::hash::{hash_data, hash_transition};
use ovp::merkle::verify_proof;
use ovp::transition::verify_transition;
use ovp::types::*;
use ed25519_dalek::SigningKey;

// 1. Define a step function (your computation)
fn my_step(state: &[u8], inputs: &[u8]) -> Vec<u8> {
    let val = u32::from_le_bytes(state[..4].try_into().unwrap());
    let add = inputs[0] as u32;
    (val + add).to_le_bytes().to_vec()
}

// 2. Execute computation and record checkpoint hashes
let mut states = vec![0u32.to_le_bytes().to_vec()];
let mut checkpoints = Vec::new();
let inputs = vec![vec![1u8], vec![2], vec![3], vec![4]];

for input in &inputs {
    let prev = states.last().unwrap();
    let next = my_step(prev, input);
    let th = hash_transition(&hash_data(prev), &hash_data(input), &hash_data(&next));
    checkpoints.push(th);
    states.push(next);
}

// 3. Build and sign commitment
let wasm_hash = hash_data(b"my_step_v1");
let (commitment, tree) = create_commitment(&checkpoints, &wasm_hash);

let key = SigningKey::from_bytes(&[0x42; 32]);
let signed = sign_commitment(&commitment, &key);
assert!(verify_signed_commitment(&signed).is_ok());

// 4. Verify any checkpoint with a Merkle proof
let proof = tree.generate_proof(0).unwrap();
assert!(verify_proof(&proof));

// 5. Full re-execution verification
let tp = TransitionProof {
    merkle_proof: proof,
    previous_state: states[0].clone(),
    previous_state_hash: hash_data(&states[0]),
    inputs: inputs[0].clone(),
    input_hash: hash_data(&inputs[0]),
    claimed_state_hash: hash_data(&states[1]),
    checkpoint_index: 0,
};
assert!(verify_transition(&commitment, &tp, &my_step).is_ok());
```

## Architecture

```
ovp/
  src/
    lib.rs           Module declarations
    types.rs         Core data types with canonical binary serialization
    hash.rs          SHA-256 hash functions with domain separation
    chain.rs         Sequential hash chain construction
    merkle.rs        Merkle tree: build, prove, verify
    commitment.rs    Commitment creation, Ed25519 signing, verification
    transition.rs    Transition verification via full re-execution
    fraud.rs         Fraud proof generation and validation
    bisection.rs     Interactive bisection dispute state machine
    zk.rs            ZK escalation (Mock proof type)
    snitch.rs        Code integrity checks and attestation
    error.rs         Error types
  tests/
    full_protocol.rs Integration tests (happy path, fraud, edge cases)
  spec.md            OVP Core Specification v0.1
```

## Protocol Flow

```
Prover                          Verifier                    Challenger
  │                                │                            │
  ├─ Execute computation           │                            │
  ├─ Record checkpoint hashes      │                            │
  ├─ Build Merkle tree + chain     │                            │
  ├─ Publish Commitment ──────────>│                            │
  │                                ├─ Verify signature          │
  │                                ├─ Request Merkle proofs     │
  │<── Send proofs ────────────────┤                            │
  │                                ├─ Verify all proofs         │
  │                                ├─ ACCEPT (optimistic)       │
  │                                │                            │
  │                          If any proof fails:                │
  │                                ├─ Initiate dispute ────────>│
  │                                │                            ├─ Re-execute
  │<──────── Bisection protocol (O(log n) rounds) ────────────>│
  │                                │                            │
  │                          Narrowed to single step:           │
  │<── Prove step or lose ─────────┤                            │
  │                                ├─ Settlement enforces       │
```

## Domain Separation

All hash contexts use domain-separated prefixes to prevent cross-context collisions:

| Context | Prefix | Function | Input size |
|---------|--------|----------|-----------|
| Merkle interior nodes | (none) | `hash_combine(left, right)` | 64 bytes |
| Checkpoint leaves | `0x00` | `hash_leaf(data)` | 1 + len |
| Transition binding | `0x01` | `hash_transition(prev, input, claimed)` | 97 bytes |
| Hash chain links | `0x02` | `hash_chain_step(tip, state)` | 65 bytes |

## Testing

```sh
cargo test          # 59 tests (46 unit + 13 integration)
cargo clippy        # 0 warnings
```

The test suite validates against all test vectors from the specification (Appendix B):
- `hash_data` — 4 vectors including empty input
- `hash_combine` — zero-hash combination
- Commitment canonical encoding — exact 104-byte layout
- DisputeProof encoding — exact 138-byte layout
- Merkle proof walkthrough — Appendix A.5 index-2 proof

Integration tests cover:
- Full happy path (8-step computation through commit/sign/verify)
- Fraud detection and bisection narrowing
- Corrupted/truncated Merkle proofs
- Wrong signing key rejection
- Defender lying about midpoint/state
- Timeout resolution
- Edge cases (empty commitment, single checkpoint)

## Benchmarks

Run with `cargo bench`. Results below from criterion on a single core.

### Primitive Operations

| Operation | Time | Notes |
|-----------|------|-------|
| `hash_data` (32B) | ~42 ns | Raw SHA-256 |
| `hash_data` (1KB) | ~680 ns | Sublinear — SHA-256 block alignment |
| `hash_combine` | ~54 ns | Merkle interior node (64B) |
| `hash_leaf` (32B) | ~54 ns | Domain prefix + 32B |
| `hash_transition` | ~70 ns | Domain prefix + 96B (crosses SHA block boundary) |
| `hash_chain_step` | ~69 ns | Domain prefix + 64B |
| Ed25519 sign | ~11 µs | Fixed cost per commitment |
| Ed25519 verify | ~23 µs | Fixed cost per verification |
| Serialization | 2–47 ns | Negligible for all types |

### Scaling

| Component | 32 | 100 | 1,000 | 10,000 | Complexity |
|-----------|----|-----|-------|--------|------------|
| Hash chain build | 2.4 µs | 7.5 µs | 75 µs | 751 µs | O(n) |
| Merkle tree build | 2.0 µs | 5.5 µs | 55 µs | 585 µs | O(n) |
| Merkle prove | 58 ns | 68 ns | 80 ns | 97 ns | O(log n) |
| Merkle verify | 324 ns | 497 ns | 710 ns | 932 ns | O(log n) |
| Bisection dispute | 129 ns | — | — | 152 ns | O(log n) |
| Commit + sign | 15 µs | 42 µs | 135 µs | — | O(n) |
| Verify all proofs | 13 µs | 64 µs | 773 µs | — | O(n log n) |

### Protocol Operations

| Operation | Time |
|-----------|------|
| Transition verify (single step) | ~686 ns |
| Fraud proof generate | ~847 ns |
| Fraud proof validate | ~527 ns |

### Protocol Overhead vs. Raw Computation

OVP adds ~196 ns of hashing per computation step (3 `hash_data` + 1 `hash_transition`). The overhead ratio depends entirely on step function cost:

| Step function cost | OVP overhead/step | Overhead ratio |
|-------------------|-------------------|----------------|
| ~2 ns (trivial counter) | 196 ns | 100x |
| 1 µs (JSON parse) | 196 ns | 0.2x |
| 100 µs (image resize) | 196 ns | 0.002x |
| 10 ms (ML inference) | 196 ns | 0.00002x |

For the target use cases (AI inference, physics simulation, media processing), per-step overhead is effectively invisible. The dominant fixed costs are Ed25519 sign (11 µs, once per batch) and verify (23 µs, once per verifier).

**Throughput**: ~7,400 batches/sec of 1,000-step commitments on a single core.

### Bottleneck Ranking

| Rank | Bottleneck | Cost | When |
|------|-----------|------|------|
| 1 | Ed25519 verify | 23 µs | Once per commitment verification |
| 2 | Ed25519 sign | 11 µs | Once per commitment creation |
| 3 | Merkle tree build | ~59 ns/leaf | Linear in checkpoint count |
| 4 | Hash chain build | ~75 ns/step | Linear in checkpoint count |
| 5 | Merkle proof verify | ~932 ns max | Per-proof, logarithmic depth |

## Dependencies

| Crate | Purpose |
|-------|---------|
| `sha2` | SHA-256 (FIPS 180-4) |
| `ed25519-dalek` | Ed25519 signatures (RFC 8032) |
| `thiserror` | Error type derivation |
| `serde` | JSON/debug serialization |
| `rand` | Key generation in tests |

## Specification

The full protocol specification is in [spec.md](spec.md). It covers:

- Protocol roles (Prover, Verifier, Challenger, Settlement Layer)
- Core data types with canonical binary encoding
- Merkle tree construction with odd-element duplication
- Challenge-response protocol with deterministic PRNG
- Transition verification via re-execution
- Fraud proof generation and settlement
- Interactive bisection dispute protocol (O(log n) rounds)
- ZK escalation for on-chain resolution
- Economic security model (slashing, catch rates)
- Code integrity via the Snitch Protocol

## License

TBD
