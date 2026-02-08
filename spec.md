# Optimistic Verification Protocol (OVP)

## Core Specification v0.1

```
Status:         Draft
Version:        0.1
Date:           2026-01-31
Authors:        Optimistic VM Contributors
```

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Protocol Overview](#2-protocol-overview)
3. [Core Data Types](#3-core-data-types)
4. [Hash Functions](#4-hash-functions)
5. [Hash Chain Construction](#5-hash-chain-construction)
6. [Merkle Tree Construction](#6-merkle-tree-construction)
7. [Commitment Protocol](#7-commitment-protocol)
8. [Challenge-Response Protocol](#8-challenge-response-protocol)
9. [Transition Verification](#9-transition-verification)
10. [Fraud Proof Protocol](#10-fraud-proof-protocol)
11. [Bisection Dispute Protocol](#11-bisection-dispute-protocol)
12. [ZK Escalation Protocol](#12-zk-escalation-protocol)
13. [Economic Security Model](#13-economic-security-model)
14. [Code Integrity (Snitch Protocol)](#14-code-integrity-snitch-protocol)
15. [Security Considerations](#15-security-considerations)
16. [Extension Points](#16-extension-points)
- [Appendix A: Canonical Encoding Reference](#appendix-a-canonical-encoding-reference)
- [Appendix B: Test Vectors](#appendix-b-test-vectors)
- [Appendix C: Reference Money Plot](#appendix-c-reference-money-plot)

---

## 1. Introduction

### 1.1 Purpose and Scope

This document specifies the Optimistic Verification Protocol (OVP), a protocol for verifying arbitrary computations without re-executing them. OVP provides cryptographic and economic guarantees that computations were performed correctly, using a combination of Merkle commitments, random sampling, interactive bisection disputes, and zero-knowledge proof escalation.

The protocol is designed to be:

- **Language-agnostic**: Implementable in any programming language
- **Domain-agnostic**: Applicable to any deterministic computation (AI inference, game physics, serverless functions, media processing)
- **Settlement-agnostic**: Compatible with any settlement layer (EVM chains, centralized arbitration, or other consensus mechanisms)

This specification defines the core protocol. Domain-specific applications (AI inference verification, gaming anti-cheat, media authenticity) are defined in separate Profile documents.

### 1.2 Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

| Term | Definition |
|------|-----------|
| **Prover** | Entity that executes a computation and produces a commitment to its execution trace |
| **Verifier** | Entity that checks a prover's commitment by sampling random checkpoints |
| **Challenger** | Entity that disputes a commitment by re-executing a specific computation step |
| **Settlement Layer** | System that enforces dispute outcomes (slashing, rewards) |
| **Checkpoint** | A hash of the computation state at a specific point in the execution trace |
| **Commitment** | A 104-byte structure binding a Merkle root, checkpoint count, hash chain tip, and code hash |
| **Slashing** | Economic penalty applied to a prover found to have committed fraud |
| **Snitch** | Report that a node is running non-canonical code, triggering immediate slashing |

### 1.3 Notation Conventions

- `||` denotes byte concatenation
- `[0x00; 32]` denotes 32 bytes of zero
- All integers are encoded as unsigned unless otherwise specified
- `LE` denotes little-endian byte order
- `BE` denotes big-endian byte order
- `SHA256(x)` denotes the SHA-256 hash function producing 32 bytes
- Hexadecimal values are prefixed with `0x`

---

## 2. Protocol Overview

### 2.1 Roles

The protocol defines four roles:

**Prover**: Executes a computation, records checkpoints at defined intervals, constructs a Merkle tree and hash chain from the checkpoints, and publishes a 104-byte Commitment. The prover stakes collateral proportional to the slashing multiplier.

**Verifier**: Receives a Commitment, derives a deterministic challenge seed, samples random checkpoint indices, requests Merkle proofs for those indices, and verifies the proofs mathematically. The verifier does NOT re-execute the computation.

**Challenger**: When fraud is suspected, the challenger initiates a dispute. Through an interactive bisection protocol, the dispute is narrowed to a single computation step. The defender (prover) must prove the step is correct or lose by default.

**Settlement Layer**: Enforces the economic outcomes of disputes. Accepts fraud proofs, verifies them, slashes dishonest provers, and rewards challengers. This role is abstract and may be implemented as a smart contract, a centralized service, or any other adjudication mechanism.

### 2.2 Protocol Phases

```
Phase 1: COMMIT
  Prover executes computation
  Prover records checkpoint hashes at each step
  Prover builds Merkle tree + hash chain
  Prover publishes Commitment (104 bytes)

Phase 2: CHALLENGE
  Verifier derives seed from commitment root
  Verifier samples random checkpoint indices via PRNG
  Verifier sends Challenge messages to prover

Phase 3: RESPOND
  Prover generates Merkle proofs for challenged indices
  Prover sends proofs to verifier

Phase 4: ACCEPT or DISPUTE
  If all proofs verify:
    Verifier accepts the commitment (optimistic path)
  If any proof fails:
    Verifier initiates dispute (rare path)
    Bisection narrows dispute to single step
    ZK proof or re-execution resolves dispute
    Settlement layer enforces outcome
```

### 2.3 Trust Model

OVP assumes a **rational adversary** model. Participants are assumed to act in their economic self-interest. The protocol does not rely on honesty; instead, it makes dishonesty economically irrational through slashing.

**Assumptions:**

1. The hash function (SHA-256) is collision-resistant
2. The signature scheme (Ed25519) is unforgeable
3. Provers are rational (they will not cheat if cheating has negative expected value)
4. At least one honest verifier exists in the network
5. Dispute resolution requires at least one challenger who has independently computed the correct result for the disputed execution trace
5. The settlement layer correctly enforces slashing and rewards
6. The step function (domain-specific computation) is deterministic

### 2.4 Threat Model

**In scope:**

- Lazy provers (skip computation, submit garbage)
- Selective cheaters (cheat on some checkpoints, honest on others)
- Colluding provers (multiple provers coordinating fraud)
- Data withholding (prover deletes state to prevent challenges)

**Out of scope:**

- Compromise of SHA-256 or Ed25519
- Irrational adversaries (willing to lose money to cause harm)
- Settlement layer failures
- Network-level attacks (eclipse, DoS)

---

## 3. Core Data Types

All multi-byte integers MUST be encoded as specified (LE or BE) in the canonical binary format. Implementations MUST use the canonical encoding for hashing and signing operations.

### 3.1 Hash

A 32-byte value produced by SHA-256.

```
Hash := [u8; 32]
```

The zero hash is defined as 32 bytes of `0x00`:

```
ZERO_HASH := [0x00; 32]
```

### 3.2 Commitment

A binding to a computation trace.

| Field | Type | Offset | Size | Encoding |
|-------|------|--------|------|----------|
| root | Hash | 0 | 32 | raw bytes |
| total_checkpoints | uint64 | 32 | 8 | little-endian |
| chain_tip | Hash | 40 | 32 | raw bytes |
| wasm_hash | Hash | 72 | 32 | raw bytes |

**Canonical size: 104 bytes**

**Fields:**

- `root`: Merkle root of all checkpoint hashes (Section 6)
- `total_checkpoints`: Number of checkpoints in the execution trace
- `chain_tip`: Final value of the sequential hash chain (Section 5)
- `wasm_hash`: SHA-256 hash of the code (WASM bytecode or equivalent) that produced this commitment. Used for code integrity verification (Section 14)

The canonical byte encoding is:

```
Commitment.to_bytes() :=
  root[0..32] || total_checkpoints_as_u64_LE[0..8] || chain_tip[0..32] || wasm_hash[0..32]
```

Implementations MUST use this exact encoding for signing operations.

### 3.3 SignedCommitment

A Commitment with an Ed25519 signature for non-repudiation.

| Field | Type | Offset | Size | Encoding |
|-------|------|--------|------|----------|
| commitment | Commitment | 0 | 104 | as defined in 3.2 |
| signature | [u8; 64] | 104 | 64 | raw Ed25519 signature |
| public_key | [u8; 32] | 168 | 32 | Ed25519 verifying key |

**Canonical size: 200 bytes**

The signature MUST be computed over `Commitment.to_bytes()` (104 bytes) using Ed25519 as specified in [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032).

**Verification procedure:**

1. Reconstruct the message: `message = commitment.to_bytes()`
2. Verify the Ed25519 signature: `Ed25519_Verify(public_key, message, signature)`

### 3.4 ProofNode

A node in a Merkle proof path.

| Field | Type | Offset | Size | Encoding |
|-------|------|--------|------|----------|
| hash | Hash | 0 | 32 | raw bytes |
| is_left | bool | 32 | 1 | 0x00 = false, 0x01 = true |

**Canonical size: 33 bytes**

The `is_left` field indicates whether this sibling node is on the LEFT side of the hash combination. When `is_left` is true, the combined hash is `hash_combine(sibling, current)`. When false, it is `hash_combine(current, sibling)`.

### 3.5 MerkleProof

An inclusion proof for a leaf in the Merkle tree.

| Field | Type | Offset | Size | Encoding |
|-------|------|--------|------|----------|
| leaf | Hash | 0 | 32 | raw bytes |
| leaf_index | uint64 | 32 | 8 | little-endian |
| sibling_count | uint32 | 40 | 4 | big-endian |
| siblings | ProofNode[] | 44 | 33 * sibling_count | as defined in 3.4 |
| root | Hash | 44 + 33*N | 32 | raw bytes |
| wasm_hash | Hash | 76 + 33*N | 32 | raw bytes |

**Variable size: 108 + 33 * sibling_count bytes**

> **Encoding note**: `sibling_count` uses big-endian encoding for alignment with standard network byte order conventions for length-prefixed fields. All other integer fields in the protocol use little-endian.

**Fields:**

- `leaf`: The checkpoint hash being proven
- `leaf_index`: Position of this leaf in the tree (0-indexed)
- `sibling_count`: Number of sibling nodes in the proof path
- `siblings`: Ordered list of sibling nodes from leaf to root
- `root`: Expected Merkle root (MUST match the commitment root)
- `wasm_hash`: Code identity hash (Section 14)

### 3.6 Challenge

A request to prove a specific checkpoint.

| Field | Type | Offset | Size | Encoding |
|-------|------|--------|------|----------|
| checkpoint_index | uint64 | 0 | 8 | little-endian |
| seed | uint64 | 8 | 8 | little-endian |

**Canonical size: 16 bytes**

### 3.7 TransitionProof

A proof that a state transition was computed correctly. Extends MerkleProof with the data needed for re-execution.

| Field | Type | Description |
|-------|------|-------------|
| merkle_proof | MerkleProof | Inclusion proof in the Merkle tree |
| previous_state | bytes | Serialized state at checkpoint N-1 |
| previous_state_hash | Hash | SHA256(previous_state) |
| inputs | bytes | Input data for the transition |
| input_hash | Hash | SHA256(inputs) |
| claimed_state_hash | Hash | Prover's claimed output state hash |
| checkpoint_index | uint64 | Index of the checkpoint being proven |

The Merkle leaf for a transition proof is the **transition hash**:

```
transition_hash := hash_transition(previous_state_hash, input_hash, claimed_state_hash)
```

This value (97 bytes of input to SHA-256, including the domain prefix) MUST equal `merkle_proof.leaf`.

### 3.8 FraudProof

Evidence that a prover submitted an incorrect computation.

| Field | Type | Description |
|-------|------|-------------|
| checkpoint_index | uint64 | Index of the fraudulent checkpoint |
| commitment_root | Hash | Root of the commitment being challenged |
| merkle_proof | MerkleProof | Proof that the claimed hash is in the tree |
| previous_state | bytes | State at checkpoint N-1 |
| previous_hash | Hash | SHA256(previous_state) |
| inputs | bytes | Inputs for the transition |
| claimed_hash | Hash | Hash claimed by prover (from Merkle leaf) |
| computed_hash | Hash | Hash computed by challenger (from re-execution) |
| challenger_id | bytes | Identity of the challenger |

A FraudProof is valid when ALL of the following hold:

1. `claimed_hash != computed_hash`
2. `merkle_proof.verify() == true`
3. `merkle_proof.root == commitment_root`

### 3.9 DisputeProof

A zero-knowledge proof for on-chain dispute resolution.

| Field | Type | Offset | Size | Encoding |
|-------|------|--------|------|----------|
| proof_type | uint8 | 0 | 1 | see table below |
| proof_length | uint32 | 1 | 4 | big-endian |
| proof_bytes | bytes | 5 | proof_length | raw bytes |
| public_inputs | Hash | 5 + N | 32 | raw bytes |
| input_hash | Hash | 37 + N | 32 | raw bytes |
| output_hash | Hash | 69 + N | 32 | raw bytes |
| wasm_hash | Hash | 101 + N | 32 | raw bytes |

**Variable size: 133 + proof_length bytes**

**Proof Type Registry:**

| Value | Name | Description |
|-------|------|-------------|
| 0x00 | Mock | Testing only; MUST NOT be used in production |
| 0x01 | RiscZeroGroth16 | RISC Zero with Groth16 wrapping |
| 0x02 | RiscZeroStark | RISC Zero native STARK |
| 0x03 | SP1 | Succinct SP1 proof |
| 0x04 | Binius | Binius binary field proof |
| 0x05-0xFF | Reserved | For future proof systems |

**Public inputs** MUST be computed as:

```
public_inputs := SHA256(input_hash || output_hash)
```

### 3.10 CodeAttestation

A signed statement binding a node to a specific code version.

| Field | Type | Offset | Size | Encoding |
|-------|------|--------|------|----------|
| node_id | [u8; 32] | 0 | 32 | raw bytes |
| wasm_hash | Hash | 32 | 32 | raw bytes |
| tick | uint64 | 64 | 8 | little-endian |
| signature | [u8; 64] | 72 | 64 | Ed25519 signature |

**Canonical size: 136 bytes**

The signature MUST be computed over:

```
sign_message := node_id[0..32] || wasm_hash[0..32] || tick_as_u64_LE[0..8]
```

This is 72 bytes of message data, signed with Ed25519.

---

## 4. Hash Functions

OVP uses two hash operations. Implementations MUST use SHA-256 as defined in [FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final).

### 4.1 hash_data

Hash arbitrary input bytes to a 32-byte digest.

```
hash_data(input: bytes) -> Hash:
  return SHA256(input)
```

### 4.2 hash_combine

Combine two hashes into one. Used only for Merkle tree interior nodes.

```
hash_combine(left: Hash, right: Hash) -> Hash:
  return SHA256(left || right)
```

The input to SHA-256 is exactly 64 bytes: the 32-byte `left` hash concatenated with the 32-byte `right` hash.

### 4.3 Domain-Separated Hash Functions

To prevent cross-context hash collisions, the following domain-separated variants MUST be used in their respective contexts:

```
DOMAIN_LEAF       = 0x00
DOMAIN_TRANSITION = 0x01
DOMAIN_CHAIN      = 0x02
```

**hash_leaf**: Hash a checkpoint's raw data with leaf domain separation.

```
hash_leaf(data: bytes) -> Hash:
  return SHA256(0x00 || data)
```

**hash_transition**: Bind a state transition with domain separation (Section 9).

```
hash_transition(prev_hash: Hash, input_hash: Hash, claimed_hash: Hash) -> Hash:
  return SHA256(0x01 || prev_hash || input_hash || claimed_hash)
```

The input to SHA-256 is exactly 97 bytes: 1 domain byte + three 32-byte hashes.

**hash_chain_step**: Append to the hash chain with domain separation (Section 5).

```
hash_chain_step(tip: Hash, state_hash: Hash) -> Hash:
  return SHA256(0x02 || tip || state_hash)
```

The input to SHA-256 is exactly 65 bytes: 1 domain byte + two 32-byte hashes.

`hash_combine` (Section 4.2) is used **only** for Merkle tree interior nodes and does NOT use a domain prefix. Tree structure inherently prevents collisions with other hash contexts.

---

## 5. Hash Chain Construction

A hash chain provides a sequential commitment to an ordered series of checkpoint hashes. Each entry depends on all previous entries, making any tampering detectable.

### 5.1 Initialization

```
chain.tip := ZERO_HASH    // [0x00; 32]
chain.length := 0
```

### 5.2 Append Operation

```
chain.append(state_hash: Hash):
  chain.tip := hash_chain_step(chain.tip, state_hash)
  chain.length := chain.length + 1
```

The hash chain is computed as:

```
H_0 = hash_chain_step(ZERO_HASH, state_hash_0)
H_1 = hash_chain_step(H_0, state_hash_1)
H_2 = hash_chain_step(H_1, state_hash_2)
...
H_n = hash_chain_step(H_{n-1}, state_hash_n)
```

### 5.3 Properties

1. **Deterministic**: Given the same sequence of state hashes, the chain tip is identical
2. **Tamper-evident**: Changing any single state hash changes the final chain tip
3. **Order-dependent**: Reordering state hashes produces a different chain tip

The chain tip is included in the Commitment (Section 3.2) as the `chain_tip` field.

---

## 6. Merkle Tree Construction

The Merkle tree provides O(log n) inclusion proofs for any checkpoint. Implementations MUST follow this exact construction to ensure interoperability.

### 6.1 Building the Tree

Given an ordered list of leaf hashes `leaves[0..n]`:

```
function build_merkle_tree(leaves: Hash[]) -> MerkleTree:
  if leaves is empty:
    return tree with root = ZERO_HASH

  layers := [leaves]           // layers[0] = leaf layer
  current_layer := leaves

  while length(current_layer) > 1:
    next_layer := []

    for i in 0..length(current_layer) step 2:
      if i + 1 < length(current_layer):
        // Pair exists: hash left and right children
        node := hash_combine(current_layer[i], current_layer[i + 1])
      else:
        // Odd element: duplicate the last leaf
        node := hash_combine(current_layer[i], current_layer[i])

      append node to next_layer

    append next_layer to layers
    current_layer := next_layer

  root := current_layer[0]
  return tree with layers and root
```

**Critical rule**: When a layer has an odd number of elements, the last element MUST be duplicated: `hash_combine(element, element)`. This is NOT the same as promoting the element unchanged.

### 6.2 Proof Generation

To generate a proof for `leaf_index`:

```
function generate_proof(tree: MerkleTree, leaf_index: uint) -> MerkleProof:
  if leaf_index >= length(tree.leaves):
    return error

  siblings := []
  current_index := leaf_index

  // Traverse from leaf layer to root (excluding root layer)
  for layer in tree.layers[0 .. length(tree.layers) - 1]:
    if current_index is even:
      sibling_index := current_index + 1
    else:
      sibling_index := current_index - 1

    if sibling_index < length(layer):
      sibling_hash := layer[sibling_index]
    else:
      // Edge case: odd layer, duplicate self
      sibling_hash := layer[current_index]

    is_left := (current_index is odd)
    // is_left means: this sibling is on the LEFT of the current node

    append ProofNode { hash: sibling_hash, is_left: is_left } to siblings
    current_index := current_index / 2   // integer division

  return MerkleProof {
    leaf: tree.leaves[leaf_index],
    leaf_index: leaf_index,
    siblings: siblings,
    root: tree.root,
    wasm_hash: ZERO_HASH   // set by caller
  }
```

### 6.3 Proof Verification

```
function verify_proof(proof: MerkleProof) -> bool:
  current := proof.leaf

  for node in proof.siblings:
    if node.is_left:
      current := hash_combine(node.hash, current)
    else:
      current := hash_combine(current, node.hash)

  return current == proof.root
```

Implementations MUST reject proofs where the recomputed root does not exactly equal `proof.root`.

---

## 7. Commitment Protocol

### 7.1 Creating a Commitment

A Prover MUST create a Commitment as follows:

1. Execute the computation, recording a checkpoint hash at each step
2. Build a hash chain from the sequence of checkpoint hashes (Section 5)
3. Build a Merkle tree from the same sequence of checkpoint hashes (Section 6)
4. Construct the Commitment:
   - `root` := Merkle tree root
   - `total_checkpoints` := number of checkpoints recorded
   - `chain_tip` := hash chain tip after all appends
   - `wasm_hash` := SHA-256 hash of the code being executed

The hash chain and Merkle tree MUST be built from the **same** ordered sequence of checkpoint hashes.

### 7.2 Signing a Commitment

A Prover SHOULD sign the Commitment to provide non-repudiation.

```
function sign_commitment(commitment: Commitment, signing_key: Ed25519SigningKey) -> SignedCommitment:
  message := commitment.to_bytes()    // 104 bytes, canonical encoding
  signature := Ed25519_Sign(signing_key, message)
  public_key := Ed25519_PublicKey(signing_key)

  return SignedCommitment {
    commitment: commitment,
    signature: signature,
    public_key: public_key
  }
```

### 7.3 Verifying a SignedCommitment

```
function verify_signed_commitment(sc: SignedCommitment) -> bool:
  message := sc.commitment.to_bytes()
  return Ed25519_Verify(sc.public_key, message, sc.signature)
```

A Verifier MUST reject any SignedCommitment where `verify_signed_commitment` returns false.

---

## 8. Challenge-Response Protocol

### 8.1 State Machine

```
                 verifier samples
[Committed] ─────────────────────> [Challenged]
                                       │
                              prover responds
                                       │
                                       ▼
                                [ProofsReceived]
                                   /        \
                          all valid           any invalid
                              /                    \
                             ▼                      ▼
                        [Accepted]             [Disputed]
```

### 8.2 Challenge Seed Derivation

The challenge seed MUST be derived deterministically from the commitment root:

```
seed := LE_uint64(commitment.root[0..8])
```

This takes the first 8 bytes of the Merkle root and interprets them as a little-endian unsigned 64-bit integer.

This ensures:
- Any party can independently derive the same challenges
- The prover cannot predict challenges before publishing the commitment
- Challenge generation is auditable

### 8.3 Pseudo-Random Number Generator

OVP uses a Linear Congruential Generator (LCG) for challenge index sampling. This PRNG is chosen for its simplicity and trivial portability across languages.

```
LCG_MULTIPLIER := 6364136223846793005    // 0x5851F42D4C957F2D
LCG_INCREMENT  := 1

function lcg_next(state: uint64) -> uint64:
  return (state * LCG_MULTIPLIER + LCG_INCREMENT) mod 2^64
  // wrapping unsigned 64-bit multiplication and addition
```

### 8.4 Challenge Generation

```
function sample_challenges(
  commitment: Commitment,
  samples_per_verification: uint
) -> Challenge[]:

  n := commitment.total_checkpoints
  if n == 0:
    return []

  sample_count := min(samples_per_verification, n)
  seed := LE_uint64(commitment.root[0..8])
  rng_state := seed
  selected := {}       // set of selected indices
  challenges := []

  while length(selected) < sample_count:
    rng_state := lcg_next(rng_state)
    index := rng_state mod n

    if index not in selected:
      add index to selected
      append Challenge { checkpoint_index: index, seed: seed } to challenges

  return challenges
```

Implementations MUST generate **unique** indices. If the LCG produces a duplicate index, the implementation MUST advance the PRNG state and retry until a unique index is produced.

### 8.5 Proof Verification

For each Challenge, the Verifier receives a MerkleProof and verifies:

```
function verify_challenge_response(
  commitment: Commitment,
  proof: MerkleProof
) -> bool:

  // 1. Root must match commitment
  if proof.root != commitment.root:
    return false

  // 2. Merkle proof must be valid
  return verify_proof(proof)    // Section 6.3
```

A Verifier MUST verify ALL proofs. If ANY proof fails, the Verifier SHOULD initiate a dispute.

### 8.6 Default Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| samples_per_verification | 2 | Number of checkpoints to sample per round |
| slashing_multiplier | 100.0 | Stake / reward ratio |

These defaults provide economic security with as few as 32 checkpoints (6.1% catch rate, well above the 1% minimum for 100x slashing).

Implementations SHOULD allow these parameters to be configured.

---

## 9. Transition Verification

Transition verification extends basic Merkle proof verification with **re-execution**. This is used when deeper verification is required (e.g., during dispute investigation).

### 9.1 Transition Hash

When using transition proofs, the Merkle leaf is NOT the raw state hash. Instead, it is a **transition hash** that binds the previous state, inputs, and claimed output:

```
transition_hash := hash_transition(previous_state_hash, input_hash, claimed_state_hash)
```

As defined in Section 4.3, the input to SHA-256 is exactly 97 bytes: the domain prefix `0x01` followed by three concatenated 32-byte hashes.

### 9.2 Verification Algorithm

```
function verify_transition(
  commitment: Commitment,
  proof: TransitionProof,
  step_fn: function(state: bytes, inputs: bytes) -> bytes,
  hash_fn: function(state: bytes) -> Hash
) -> TransitionVerificationResult:

  // Step 1: Verify Merkle inclusion
  if not verify_challenge_response(commitment, proof.merkle_proof):
    return FAILURE("Merkle proof failed")

  // Step 2: Verify transition hash matches Merkle leaf
  expected := hash_transition(
    proof.previous_state_hash,
    proof.input_hash,
    proof.claimed_state_hash
  )
  if proof.merkle_proof.leaf != expected:
    return FAILURE("Transition hash mismatch")

  // Step 3: Verify previous state hash
  computed_prev := hash_data(proof.previous_state)
  if computed_prev != proof.previous_state_hash:
    return FAILURE("Previous state hash mismatch")

  // Step 4: Verify input hash
  computed_input := hash_data(proof.inputs)
  if computed_input != proof.input_hash:
    return FAILURE("Input hash mismatch")

  // Step 5: Re-execute the step function
  computed_state := step_fn(proof.previous_state, proof.inputs)
  computed_hash := hash_fn(computed_state)

  // Step 6: Compare computed output to claimed output
  if computed_hash != proof.claimed_state_hash:
    return FAILURE("FRAUD DETECTED: computed state doesn't match claimed state")

  return SUCCESS(computed_hash)
```

The `step_fn` and `hash_fn` are domain-specific and defined by the application profile. The default `hash_fn` is `hash_data` (SHA-256).

---

## 10. Fraud Proof Protocol

### 10.1 Generating a Fraud Proof

When a Challenger detects a mismatch between claimed and computed state:

```
function generate_fraud_proof(
  commitment: Commitment,
  checkpoint_index: uint,
  previous_state: bytes,
  inputs: bytes,
  merkle_proof: MerkleProof,
  step_fn: function(state: bytes, inputs: bytes) -> bytes,
  challenger_id: bytes
) -> DisputeResult:

  // Verify Merkle proof is valid and matches commitment
  if not verify_proof(merkle_proof):
    return InvalidChallenge("Invalid merkle proof")

  if merkle_proof.root != commitment.root:
    return InvalidChallenge("Merkle proof doesn't match commitment")

  // Re-execute
  previous_hash := hash_data(previous_state)
  new_state := step_fn(previous_state, inputs)
  computed_hash := hash_data(new_state)

  // Compare with claimed hash (the Merkle leaf)
  claimed_hash := merkle_proof.leaf

  if computed_hash != claimed_hash:
    // FRAUD CONFIRMED
    return FraudConfirmed {
      proof: FraudProof {
        checkpoint_index, commitment_root: commitment.root,
        merkle_proof, previous_state, previous_hash,
        inputs, claimed_hash, computed_hash, challenger_id
      },
      slash_amount: <from SlashingConfig>,
      reward_amount: <from SlashingConfig>
    }
  else:
    return NoFraud { checkpoint_index, reason: "Re-execution matched" }
```

### 10.2 Validating a Fraud Proof

A Settlement Layer MUST verify the following before slashing:

1. `fraud_proof.merkle_proof.verify() == true` (the claimed hash IS in the tree)
2. `fraud_proof.merkle_proof.root == fraud_proof.commitment_root` (proof matches the commitment)
3. `fraud_proof.claimed_hash != fraud_proof.computed_hash` (there IS a mismatch)
4. The re-execution is correct (Settlement Layer re-executes or accepts a ZK proof)

If all four conditions hold, the Settlement Layer MUST slash the prover and reward the challenger.

---

## 11. Bisection Dispute Protocol

The bisection protocol narrows a dispute from an arbitrary range of checkpoints to a **single step** through O(log n) interactive rounds. This solves the data availability problem: the defender (prover) bears the burden of providing state data.

### 11.1 State Machine

```
                          defender reveals midpoint
[WaitingDefenderMidpoint] ──────────────────────────> [WaitingChallengerChoice]
         ▲                                                      │
         │                                          challenger picks half
         │                                                      │
         │              ┌──────────────────────────────────────┘
         │              │
         │       if range > 1                          if range == 1
         └──────────────┘                                    │
                                                             ▼
                                                [WaitingDefenderProof]
                                                             │
                                                  defender proves step
                                                             │
                                                             ▼
                                                        [Resolved]

Any phase ──── timeout ──── > [Resolved]
                               (non-responding party loses)
```

### 11.2 Initialization

A bisection dispute is created when a challenger identifies a range `[left_index, right_index]` where:

- `left_hash` (the hash at `left_index`) is agreed to be correct
- `right_hash` (the hash at `right_index`) is claimed to be incorrect

```
dispute := BisectionDispute {
  left_index: <agreed good checkpoint>,
  right_index: <disputed checkpoint>,
  left_hash: <agreed good hash>,
  right_hash: <disputed hash>,
  phase: WaitingDefenderMidpoint,
  deadline: <current_time + round_timeout>,
  rounds: 0
}
```

Constraint: `right_index` MUST be greater than `left_index`.

### 11.3 Defender Reveals Midpoint

When the phase is `WaitingDefenderMidpoint`, the defender MUST reveal the hash at the midpoint:

```
midpoint_index := (left_index + right_index) / 2    // integer division, rounds down
```

The defender provides `midpoint_hash`, the checkpoint hash at `midpoint_index`. The phase transitions to `WaitingChallengerChoice`.

If the defender fails to respond before the deadline, the challenger wins by timeout.

### 11.4 Challenger Chooses Half

When the phase is `WaitingChallengerChoice`, the challenger picks which half contains the fraud:

- **Pick right half** (`pick_right = true`): Fraud is in `[midpoint, right]`
  - `left_index := midpoint_index`
  - `left_hash := midpoint_hash`
- **Pick left half** (`pick_right = false`): Fraud is in `[left, midpoint]`
  - `right_index := midpoint_index`
  - `right_hash := midpoint_hash`

After narrowing:

- If `right_index - left_index == 1`: phase transitions to `WaitingDefenderProof`
- Otherwise: phase transitions back to `WaitingDefenderMidpoint`

If the challenger fails to respond before the deadline, the defender wins by timeout.

### 11.5 Defender Proves Step

When narrowed to a single step (`right_index - left_index == 1`):

1. Defender provides `previous_state` (state at `left_index`) and `inputs`
2. Verify: `hash_data(previous_state) == left_hash`
3. Re-execute: `computed_output := step_fn(previous_state, inputs)`
4. Verify: `hash_data(computed_output) == right_hash`

If Step 2 fails: **Challenger wins** (defender's state doesn't match agreed checkpoint).
If Step 4 succeeds: **Defender wins** (step execution was correct).
If Step 4 fails: **Challenger wins** (step execution mismatch = fraud).

### 11.6 Timeout

Each phase has a deadline. If the deadline passes without a response:

| Phase | Non-responder | Winner |
|-------|--------------|--------|
| WaitingDefenderMidpoint | Defender | Challenger |
| WaitingChallengerChoice | Challenger | Defender |
| WaitingDefenderProof | Defender | Challenger |

### 11.7 Complexity

```
rounds_needed := ceil(log2(total_checkpoints))
max_dispute_time := (rounds_needed * 2 + 1) * round_timeout_seconds
```

For 1000 checkpoints: 10 rounds, 21 timeout periods.

---

## 12. ZK Escalation Protocol

When the bisection protocol identifies a single disputed step, either party MAY escalate to a zero-knowledge proof for trustless on-chain resolution.

### 12.1 Proof Generation

The defending prover generates a ZK proof demonstrating:

> "Given input state with hash `input_hash` and computation logic with hash `wasm_hash`, the output state has hash `output_hash`."

### 12.2 Public Inputs

The public inputs for any ZK proof MUST be:

```
public_inputs := hash_data(input_hash || output_hash)
```

This is a 32-byte hash derived from the 64-byte concatenation of input and output hashes.

### 12.3 Proof Type Registry

Implementations MUST support at least proof type `0x00` (Mock) for testing.

Implementations SHOULD support at least one production proof type (`0x01` through `0x04`).

| Type | System | Typical Overhead | On-Chain Gas |
|------|--------|-----------------|-------------|
| 0x01 | RISC Zero Groth16 | ~1000x | ~300k |
| 0x02 | RISC Zero STARK | ~500x | ~500k |
| 0x03 | SP1 | ~1000x | ~250k |
| 0x04 | Binius | ~200x | ~200k |

New proof types in the range `0x05` to `0xFF` MAY be registered through the extension mechanism (Section 16).

### 12.4 Binary Encoding

The DisputeProof binary encoding is defined in Section 3.9. Implementations MUST use this exact format for serialization and deserialization.

### 12.5 Verification

Proof verification is proof-system-specific and outside the scope of this core specification. Each proof system defines its own verification algorithm. The Settlement Layer MUST verify:

1. `public_inputs == hash_data(input_hash || output_hash)` (public inputs are correctly derived)
2. The proof verifies under the proof-system-specific verifier
3. `wasm_hash` matches the canonical code hash for the network

---

## 13. Economic Security Model

The protocol's security derives from economic incentives, not just cryptography. Cheating is made **economically irrational** through slashing.

### 13.1 Parameters

```
SlashingConfig:
  stake_amount: uint64     // Collateral deposited by prover
  reward_amount: uint64    // Payment for successful computation
  multiplier: float64      // stake_amount / reward_amount
```

Implementations MUST default to `multiplier >= 100`.

### 13.2 Minimum Catch Rate

For the system to be economically secure, the probability of catching a cheater must exceed:

```
min_catch_rate := 1 / multiplier
```

For a 100x multiplier, this is 1%. Any catch rate above 1% makes cheating unprofitable.

### 13.3 Expected Value of Cheating

```
EV(cheat) := reward_amount * (1 - multiplier * catch_rate)
```

- When `EV(cheat) < 0`: cheating is unprofitable (SECURE)
- When `EV(cheat) > 0`: cheating may be profitable (INSECURE)
- When `EV(cheat) = 0`: break-even point

### 13.4 Single-Round Catch Rate

Given `n` total checkpoints and `s` samples per verification, the probability of catching a cheater who corrupted at least 1 checkpoint:

```
single_catch_rate := 1 - ((n - 1) / n)^s
```

This assumes uniform random sampling without replacement.

### 13.5 Cumulative Catch Rate

Over multiple independent verification rounds:

```
cumulative_catch_rate(single_catch, rounds) := 1 - (1 - single_catch)^rounds
```

### 13.6 Rounds for Target Confidence

```
rounds_for_confidence(single_catch, target) := ceil(log(1 - target) / log(1 - single_catch))
```

### 13.7 Security Margin

```
security_margin := catch_rate - min_catch_rate
```

Implementations SHOULD reject configurations where `security_margin <= 0`.

### 13.8 Reference Values

| Checkpoints | Samples | Single Catch | Min Required | Secure? |
|-------------|---------|-------------|-------------|---------|
| 32 | 2 | 6.1% | 1.0% | Yes |
| 32 | 10 | 27.1% | 1.0% | Yes |
| 100 | 2 | 2.0% | 1.0% | Yes |
| 100 | 10 | 9.6% | 1.0% | Yes |
| 1000 | 2 | 0.2% | 1.0% | **No** |
| 1000 | 10 | 1.0% | 1.0% | Borderline |

For large checkpoint counts, implementations MUST increase `samples_per_verification` to maintain security.

---

## 14. Code Integrity (Snitch Protocol)

The Snitch Protocol provides a lightweight integrity check for detecting accidental code divergence and lazy modifications. A constant-time hash comparison catches nodes running non-canonical code that honestly reports its own hash.

> **Security note**: An adversarial node can hardcode the canonical `wasm_hash` in outgoing messages while running modified code. Full adversarial code integrity requires TEE/SGX attestation (out of scope for v0.1). The primary defense against adversarial code modification is the sampling/bisection mechanism — wrong code produces wrong outputs, which get caught through the dispute protocol (Sections 10-11).

### 14.1 Canonical Hash

The network MUST agree on a canonical code hash:

```
canonical_wasm_hash := hash_data(canonical_wasm_bytecode)
```

This hash is set once at network initialization and updated only through a governance process.

### 14.2 Inclusion Requirement

Every protocol message that includes a `wasm_hash` field MUST populate it with the sender's code hash. This includes:

- Commitment (Section 3.2)
- MerkleProof (Section 3.5)
- DisputeProof (Section 3.9)
- CodeAttestation (Section 3.10)

### 14.3 Verification

Every receiving node MUST compare the `wasm_hash` in any received message against its own canonical hash:

```
function check_code_integrity(received_hash: Hash, canonical_hash: Hash) -> bool:
  return received_hash == canonical_hash
```

This is an O(1) operation (32-byte comparison).

### 14.4 Snitch Report

If `check_code_integrity` returns false:

1. The receiving node MUST reject the message
2. The receiving node SHOULD submit a snitch report to the Settlement Layer
3. The Settlement Layer MUST slash the offending node
4. The first reporter SHOULD receive a portion of the slashed stake (RECOMMENDED: 10%)

### 14.5 CodeAttestation

Nodes MAY periodically publish signed CodeAttestation messages (Section 3.10) as positive proof that they are running canonical code. Other nodes can verify these attestations and report any with non-canonical `wasm_hash`.

---

## 15. Security Considerations

### 15.1 PRNG Determinism

The LCG-based PRNG (Section 8.3) MUST produce identical output across all implementations for a given seed. This is critical for:

- Independent verification: any party can re-derive the same challenges
- Auditability: challenge selection can be verified after the fact
- Non-manipulability: prover cannot influence challenge selection (seed is derived from commitment root, which is published before challenges)

Implementations MUST use unsigned 64-bit wrapping arithmetic for the LCG.

### 15.2 Hash Comparison

Implementations SHOULD use constant-time comparison for hash equality checks to prevent timing side-channel attacks. This is especially important for:

- Code integrity checks (Section 14)
- Fraud proof validation (Section 10)
- Signature verification (Section 7)

### 15.3 Replay Protection

The `chain_tip` field in the Commitment provides implicit replay protection. Since the hash chain is sequential and depends on all previous state hashes, each commitment is unique to its execution trace.

Implementations SHOULD additionally track processed commitment IDs to prevent replay of entire commitments.

### 15.4 Data Availability

The bisection protocol (Section 11) explicitly addresses data availability:

- The **defender** (prover) bears the burden of providing state data
- If the defender cannot provide data, they lose by default
- This prevents the "delete data to escape disputes" attack

Implementations SHOULD store checkpoint state data for the duration of the dispute window.

### 15.5 Deterministic Execution

The step function `step_fn(state, inputs) -> state` MUST be deterministic. For the same inputs, every implementation MUST produce the same output.

For floating-point computations, implementations SHOULD use fixed-point arithmetic or quantized representations to ensure reproducibility across different hardware and software platforms.

### 15.6 Signature Scheme

OVP uses Ed25519 as specified in [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032). Implementations MUST NOT use Ed25519 variants (Ed25519ctx, Ed25519ph) unless explicitly specified by a profile document.

### 15.7 Integer Overflow

The `total_checkpoints` field is encoded as uint64. Implementations MUST handle the case where `total_checkpoints` is 0 (empty computation). Implementations SHOULD reject commitments where `total_checkpoints` exceeds a reasonable maximum for the domain.

---

## 16. Extension Points

### 16.1 ZK Proof Type Registry

New proof systems can be added by assigning values in the range `0x05` to `0xFF`. A new proof type registration MUST define:

1. The proof generation algorithm
2. The proof verification algorithm
3. The expected proof size range
4. Performance characteristics

### 16.2 Domain Verification Functions

The step function `step_fn(state, inputs) -> state` is intentionally left undefined by this core specification. Domain-specific Profile documents define:

- What constitutes "state" and "inputs"
- How checkpoints are derived from the computation
- What hash function to use for state (default: SHA-256)
- Checkpoint granularity (e.g., every layer for LLMs, every tick for games)

### 16.3 Settlement Layer Interface

The Settlement Layer is defined as an abstract interface. A conforming settlement layer MUST support these operations:

| Operation | Description |
|-----------|-------------|
| `submitCommitment(commitment, stake)` | Register a new commitment with staked collateral |
| `submitFraudProof(fraud_proof)` | Submit evidence of fraud for verification |
| `submitDisputeProof(dispute_proof)` | Submit a ZK proof to resolve a dispute |
| `slash(prover, amount)` | Remove stake from a dishonest prover |
| `reward(challenger, amount)` | Pay a challenger for successful fraud detection |
| `finalize(commitment_id)` | Mark a commitment as finalized after the dispute window |

Implementations MAY add additional operations as needed.

### 16.4 Protocol Versioning

This specification is version `0x0001` (v0.1).

Implementations SHOULD include a protocol version identifier in their initial handshake or message framing. The version format is a 16-bit unsigned integer in big-endian encoding.

Future versions MUST maintain backwards compatibility or define explicit migration procedures.

---

## Appendix A: Canonical Encoding Reference

This appendix provides a worked example of the complete protocol flow with exact byte values.

### A.1 Setup: 4 Checkpoints

Given 4 checkpoint hashes (each produced by `hash_data` of simple byte inputs):

```
leaf_0 := hash_data([0x00]) = SHA256(0x00)
leaf_1 := hash_data([0x01]) = SHA256(0x01)
leaf_2 := hash_data([0x02]) = SHA256(0x02)
leaf_3 := hash_data([0x03]) = SHA256(0x03)
```

### A.2 Merkle Tree Construction

```
Layer 0 (leaves):  [leaf_0, leaf_1, leaf_2, leaf_3]

Layer 1:
  node_0 := hash_combine(leaf_0, leaf_1) = SHA256(leaf_0 || leaf_1)
  node_1 := hash_combine(leaf_2, leaf_3) = SHA256(leaf_2 || leaf_3)

Layer 2 (root):
  root := hash_combine(node_0, node_1) = SHA256(node_0 || node_1)
```

### A.3 Hash Chain Construction

```
tip_0 := ZERO_HASH = [0x00; 32]
tip_1 := hash_chain_step(tip_0, leaf_0) = SHA256(0x02 || [0x00; 32] || leaf_0)
tip_2 := hash_chain_step(tip_1, leaf_1) = SHA256(0x02 || tip_1 || leaf_1)
tip_3 := hash_chain_step(tip_2, leaf_2) = SHA256(0x02 || tip_2 || leaf_2)
tip_4 := hash_chain_step(tip_3, leaf_3) = SHA256(0x02 || tip_3 || leaf_3)

chain_tip := tip_4
```

### A.4 Commitment

```
Commitment {
  root: root,                    // 32 bytes
  total_checkpoints: 4,          // encoded as 0x0400000000000000 (u64 LE)
  chain_tip: chain_tip,          // 32 bytes
  wasm_hash: <code_hash>,        // 32 bytes
}

to_bytes() = root || 0x0400000000000000 || chain_tip || wasm_hash
           = 104 bytes total
```

### A.5 Merkle Proof for Index 2

```
Proof for leaf_2 (index 2):

  Start at layer 0, index 2:
    sibling_index = 3 (2 is even, so sibling = 2+1 = 3)
    sibling = leaf_3
    is_left = false (current index 2 is even)
    ProofNode { hash: leaf_3, is_left: false }

  Move to layer 1, index 1 (2/2 = 1):
    sibling_index = 0 (1 is odd, so sibling = 1-1 = 0)
    sibling = node_0
    is_left = true (current index 1 is odd)
    ProofNode { hash: node_0, is_left: true }

Verification:
  current = leaf_2
  Step 1: is_left=false → current = hash_combine(current, leaf_3) = node_1
  Step 2: is_left=true  → current = hash_combine(node_0, current) = hash_combine(node_0, node_1) = root ✓
```

---

## Appendix B: Test Vectors

Concrete test vectors for cross-implementation validation. All hashes are SHA-256.

### B.1 hash_data

```
Input:  0x (empty)
Output: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

Input:  0x00
Output: 6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d

Input:  0x01
Output: 4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a

Input:  0x0102030405
Output: 74f81fe167d99b4cb41d6d0ccda82278caee9f3e2f25d5e5a3936ff3dcec60d0
```

### B.2 hash_combine

```
Input:  left  = [0x00; 32], right = [0x00; 32]
Output: SHA256([0x00; 64])
      = f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b

Input:  left  = [0x01; 32], right = [0x02; 32]
Output: SHA256([0x01; 32] || [0x02; 32])
```

### B.3 Hash Chain

```
Append hash_data([0x00]):
  tip_0 = ZERO_HASH
  tip_1 = hash_chain_step(ZERO_HASH, hash_data([0x00]))
        = SHA256(0x02 ||
            [0x00; 32] ||
            6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d
          )

Append hash_data([0x01]):
  tip_2 = hash_chain_step(tip_1, hash_data([0x01]))
        = SHA256(0x02 ||
            tip_1 ||
            4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a
          )
```

### B.4 LCG PRNG

```
Seed: 42

state_0 = 42
state_1 = (42 * 6364136223846793005 + 1) mod 2^64
        = 267205306969106211
index_1 = 267205306969106211 mod 100 = 11

state_2 = (267205306969106211 * 6364136223846793005 + 1) mod 2^64
index_2 = state_2 mod 100

(Full sequence for seed=42, n=100, 5 unique samples should be computed
 by running the reference implementation)
```

### B.5 Commitment Canonical Encoding

```
Given:
  root = [0xAB; 32]
  total_checkpoints = 100
  chain_tip = [0xCD; 32]
  wasm_hash = [0xEF; 32]

to_bytes():
  Bytes 0-31:   0xABABAB...AB (32 bytes of 0xAB)
  Bytes 32-39:  0x6400000000000000 (100 as u64 LE)
  Bytes 40-71:  0xCDCDCD...CD (32 bytes of 0xCD)
  Bytes 72-103: 0xEFEFEF...EF (32 bytes of 0xEF)

Total: 104 bytes
```

### B.6 DisputeProof Binary Encoding

```
Given:
  proof_type = Mock (0x00)
  proof_bytes = [0x01, 0x02, 0x03, 0x04, 0x05] (5 bytes)
  public_inputs = [0x2A; 32]
  input_hash = [0x01; 32]
  output_hash = [0x02; 32]
  wasm_hash = [0xCA; 32]

to_bytes():
  Byte 0:       0x00 (proof_type = Mock)
  Bytes 1-4:    0x00000005 (proof_length = 5, BE)
  Bytes 5-9:    0x0102030405 (proof_bytes)
  Bytes 10-41:  [0x2A; 32] (public_inputs)
  Bytes 42-73:  [0x01; 32] (input_hash)
  Bytes 74-105: [0x02; 32] (output_hash)
  Bytes 106-137: [0xCA; 32] (wasm_hash)

Total: 138 bytes
```

---

## Appendix C: Reference Money Plot

### C.1 Configuration

```
Slashing multiplier: 100x
Reward amount: 1000 units
Stake amount: 100,000 units
Checkpoints: 32
Samples per verification: 2
Single-round catch rate: 6.1%
```

### C.2 Cumulative Security Over Rounds

| Rounds | Catch Probability | EV(Cheat) | EV/Stake | Security |
|--------|-------------------|-----------|----------|----------|
| 1 | 6.1% | -5,100 | -0.051x | SECURE |
| 5 | 27.0% | -26,000 | -0.260x | SECURE |
| 10 | 46.7% | -45,700 | -0.457x | SECURE |
| 20 | 71.6% | -70,600 | -0.706x | SECURE |
| 50 | 95.3% | -94,300 | -0.943x | SECURE |
| 100 | 99.8% | -98,800 | -0.988x | SECURE |

### C.3 Interpretation

Even after a single verification round, cheating has a negative expected value of -5.1x the reward. After 10 rounds, the cumulative catch probability exceeds 46%, making the expected loss from cheating approximately 45x the reward.

A rational actor will never cheat under these parameters.

### C.4 Different Configurations

| Checkpoints | Samples | Single Catch | Rounds for 99% |
|-------------|---------|-------------|----------------|
| 32 | 2 | 6.1% | 73 |
| 32 | 5 | 14.8% | 28 |
| 32 | 10 | 27.1% | 14 |
| 64 | 2 | 3.1% | 147 |
| 64 | 10 | 14.5% | 29 |
| 100 | 2 | 2.0% | 228 |
| 100 | 10 | 9.6% | 46 |

---

## References

- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) - Key words for use in RFCs to Indicate Requirement Levels
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) - Edwards-Curve Digital Signature Algorithm (EdDSA)
- [FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final) - Secure Hash Standard (SHS)
- [RISC Zero](https://risczero.com/) - General purpose zero-knowledge virtual machine
- [SP1](https://succinctlabs.com/) - Succinct proof system
- [Binius](https://eprint.iacr.org/2023/1784) - Binary field proof system

---

*End of OVP Core Specification v0.1*
