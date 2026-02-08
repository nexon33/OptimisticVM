use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use ed25519_dalek::SigningKey;
use ovp::bisection::BisectionDispute;
use ovp::commitment::{create_commitment, sign_commitment, verify_signed_commitment};
use ovp::fraud::{generate_fraud_proof, validate_fraud_proof};
use ovp::hash::{hash_chain_step, hash_combine, hash_data, hash_leaf, hash_transition};
use ovp::merkle::{verify_proof, MerkleTree};
use ovp::snitch::{sign_attestation, verify_attestation};
use ovp::transition::verify_transition;
use ovp::types::*;
use ovp::zk::{generate_mock_proof, verify_dispute_proof};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn counter_step(state: &[u8], inputs: &[u8]) -> Vec<u8> {
    let val = u32::from_le_bytes(state[..4].try_into().unwrap());
    let add = inputs.first().copied().unwrap_or(0) as u32;
    (val + add).to_le_bytes().to_vec()
}

/// Build n checkpoints using the counter step function.
fn build_checkpoints(n: usize) -> (Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Hash>) {
    let initial = 0u32.to_le_bytes().to_vec();
    let mut states = vec![initial];
    let mut inputs = Vec::with_capacity(n);
    let mut checkpoints = Vec::with_capacity(n);

    for i in 0..n {
        let input = vec![(i % 256) as u8];
        let prev = states.last().unwrap();
        let next = counter_step(prev, &input);
        let th = hash_transition(&hash_data(prev), &hash_data(&input), &hash_data(&next));
        checkpoints.push(th);
        states.push(next);
        inputs.push(input);
    }

    (states, inputs, checkpoints)
}

// ---------------------------------------------------------------------------
// Hash primitives
// ---------------------------------------------------------------------------

fn bench_hash_primitives(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_primitives");

    let data_32 = [0xABu8; 32];
    let data_1k = vec![0xABu8; 1024];
    let left = hash_data(&[0x01]);
    let right = hash_data(&[0x02]);
    let prev = hash_data(&[0x03]);
    let input = hash_data(&[0x04]);
    let claimed = hash_data(&[0x05]);

    group.bench_function("hash_data/32B", |b| {
        b.iter(|| hash_data(black_box(&data_32)))
    });

    group.bench_function("hash_data/1KB", |b| {
        b.iter(|| hash_data(black_box(&data_1k)))
    });

    group.bench_function("hash_combine", |b| {
        b.iter(|| hash_combine(black_box(&left), black_box(&right)))
    });

    group.bench_function("hash_leaf/32B", |b| {
        b.iter(|| hash_leaf(black_box(&data_32)))
    });

    group.bench_function("hash_transition", |b| {
        b.iter(|| hash_transition(black_box(&prev), black_box(&input), black_box(&claimed)))
    });

    group.bench_function("hash_chain_step", |b| {
        b.iter(|| hash_chain_step(black_box(&left), black_box(&right)))
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Hash chain construction (scaling)
// ---------------------------------------------------------------------------

fn bench_hash_chain(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_chain");

    for &n in &[32, 100, 1000, 10_000] {
        let hashes: Vec<Hash> = (0..n).map(|i| hash_data(&(i as u32).to_le_bytes())).collect();

        group.bench_with_input(BenchmarkId::from_parameter(n), &hashes, |b, hashes| {
            b.iter(|| {
                let mut chain = ovp::chain::HashChain::new();
                for h in hashes {
                    chain.append(black_box(h));
                }
                chain.tip
            })
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Merkle tree (build, prove, verify — scaling)
// ---------------------------------------------------------------------------

fn bench_merkle_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_build");

    for &n in &[32, 100, 1000, 10_000] {
        let leaves: Vec<Hash> = (0..n).map(|i| hash_data(&(i as u32).to_le_bytes())).collect();

        group.bench_with_input(BenchmarkId::from_parameter(n), &leaves, |b, leaves| {
            b.iter(|| MerkleTree::build(black_box(leaves)))
        });
    }

    group.finish();
}

fn bench_merkle_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_prove");

    for &n in &[32, 100, 1000, 10_000] {
        let leaves: Vec<Hash> = (0..n).map(|i| hash_data(&(i as u32).to_le_bytes())).collect();
        let tree = MerkleTree::build(&leaves);

        group.bench_with_input(BenchmarkId::from_parameter(n), &tree, |b, tree| {
            b.iter(|| tree.generate_proof(black_box(0)))
        });
    }

    group.finish();
}

fn bench_merkle_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_verify");

    for &n in &[32, 100, 1000, 10_000] {
        let leaves: Vec<Hash> = (0..n).map(|i| hash_data(&(i as u32).to_le_bytes())).collect();
        let tree = MerkleTree::build(&leaves);
        let proof = tree.generate_proof(0).unwrap();

        group.bench_with_input(BenchmarkId::from_parameter(n), &proof, |b, proof| {
            b.iter(|| verify_proof(black_box(proof)))
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Commitment (create, sign, verify)
// ---------------------------------------------------------------------------

fn bench_commitment(c: &mut Criterion) {
    let mut group = c.benchmark_group("commitment");
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let wasm_hash = hash_data(b"bench_code");

    for &n in &[32, 100, 1000] {
        let (_, _, checkpoints) = build_checkpoints(n);

        group.bench_with_input(
            BenchmarkId::new("create", n),
            &checkpoints,
            |b, checkpoints| b.iter(|| create_commitment(black_box(checkpoints), &wasm_hash)),
        );
    }

    // Sign and verify at fixed size
    let (_, _, checkpoints) = build_checkpoints(100);
    let (commitment, _) = create_commitment(&checkpoints, &wasm_hash);

    group.bench_function("sign/100", |b| {
        b.iter(|| sign_commitment(black_box(&commitment), &signing_key))
    });

    let signed = sign_commitment(&commitment, &signing_key);

    group.bench_function("verify_sig/100", |b| {
        b.iter(|| verify_signed_commitment(black_box(&signed)))
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Transition verification (full re-execution)
// ---------------------------------------------------------------------------

fn bench_transition(c: &mut Criterion) {
    let mut group = c.benchmark_group("transition_verify");
    let wasm_hash = hash_data(b"counter_step_v1");

    let (states, inputs, checkpoints) = build_checkpoints(100);
    let (commitment, tree) = create_commitment(&checkpoints, &wasm_hash);
    let merkle_proof = tree.generate_proof(0).unwrap();

    let tp = TransitionProof {
        merkle_proof,
        previous_state: states[0].clone(),
        previous_state_hash: hash_data(&states[0]),
        inputs: inputs[0].clone(),
        input_hash: hash_data(&inputs[0]),
        claimed_state_hash: hash_data(&states[1]),
        checkpoint_index: 0,
    };

    group.bench_function("single_step", |b| {
        b.iter(|| verify_transition(black_box(&commitment), black_box(&tp), &counter_step))
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Fraud proof (generate + validate)
// ---------------------------------------------------------------------------

fn bench_fraud(c: &mut Criterion) {
    let mut group = c.benchmark_group("fraud_proof");
    let wasm_hash = hash_data(b"counter_step_v1");

    let (states, inputs, mut checkpoints) = build_checkpoints(100);
    checkpoints[50] = hash_data(b"bad"); // corrupt checkpoint 50
    let (commitment, tree) = create_commitment(&checkpoints, &wasm_hash);
    let proof = tree.generate_proof(50).unwrap();

    group.bench_function("generate", |b| {
        b.iter(|| {
            generate_fraud_proof(
                black_box(&commitment),
                50,
                black_box(&states[50]),
                black_box(&inputs[50]),
                proof.clone(),
                &counter_step,
                b"bench_challenger",
            )
        })
    });

    let result = generate_fraud_proof(
        &commitment,
        50,
        &states[50],
        &inputs[50],
        proof,
        &counter_step,
        b"bench_challenger",
    )
    .unwrap();

    if let FraudResult::FraudConfirmed(ref fp) = result {
        group.bench_function("validate", |b| {
            b.iter(|| validate_fraud_proof(black_box(fp), &counter_step))
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Bisection dispute (full protocol)
// ---------------------------------------------------------------------------

fn bench_bisection(c: &mut Criterion) {
    let mut group = c.benchmark_group("bisection");

    fn increment_step(state: &[u8], _inputs: &[u8]) -> Vec<u8> {
        let mut out = state.to_vec();
        for b in &mut out {
            *b = b.wrapping_add(1);
        }
        out
    }

    // Pre-compute honest hashes
    let initial = vec![0u8; 4];
    let mut states = vec![initial.clone()];
    let mut hashes = vec![hash_data(&initial)];
    for _ in 0..1024 {
        let prev = states.last().unwrap();
        let next = increment_step(prev, &[]);
        hashes.push(hash_data(&next));
        states.push(next);
    }

    for &n in &[8, 64, 256, 1024] {
        group.bench_with_input(
            BenchmarkId::new("full_dispute", n),
            &n,
            |b, &n| {
                b.iter(|| {
                    let mut dispute =
                        BisectionDispute::new(0, n as u64, hashes[0], hashes[n]).unwrap();

                    while dispute.range_width() > 1 {
                        let mid = (dispute.left_index + dispute.right_index) / 2;
                        dispute.defender_reveal_midpoint(hashes[mid as usize]).unwrap();
                        dispute.challenger_choose_half(true).unwrap();
                    }

                    dispute
                        .defender_prove_step(&states[dispute.left_index as usize], &[], &increment_step)
                        .unwrap()
                })
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// ZK mock proof
// ---------------------------------------------------------------------------

fn bench_zk_mock(c: &mut Criterion) {
    let mut group = c.benchmark_group("zk_mock");
    let input_hash = hash_data(b"input");
    let output_hash = hash_data(b"output");
    let wasm_hash = hash_data(b"code");

    group.bench_function("generate", |b| {
        b.iter(|| generate_mock_proof(black_box(&input_hash), black_box(&output_hash), black_box(&wasm_hash)))
    });

    let proof = generate_mock_proof(&input_hash, &output_hash, &wasm_hash);

    group.bench_function("verify", |b| {
        b.iter(|| verify_dispute_proof(black_box(&proof)))
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Ed25519 signing (attestation)
// ---------------------------------------------------------------------------

fn bench_attestation(c: &mut Criterion) {
    let mut group = c.benchmark_group("attestation");
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let verifying_key = signing_key.verifying_key();
    let node_id = [0xAA; 32];
    let wasm_hash = hash_data(b"canonical");

    group.bench_function("sign", |b| {
        b.iter(|| sign_attestation(black_box(&node_id), black_box(&wasm_hash), 1, &signing_key))
    });

    let att = sign_attestation(&node_id, &wasm_hash, 1, &signing_key);

    group.bench_function("verify", |b| {
        b.iter(|| verify_attestation(black_box(&att), &verifying_key))
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Serialization round-trips
// ---------------------------------------------------------------------------

fn bench_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialization");

    // Commitment
    let commitment = Commitment {
        root: [0xAB; 32],
        total_checkpoints: 100,
        chain_tip: [0xCD; 32],
        wasm_hash: [0xEF; 32],
    };

    group.bench_function("commitment/to_bytes", |b| {
        b.iter(|| black_box(&commitment).to_bytes())
    });

    let cbytes = commitment.to_bytes();
    group.bench_function("commitment/from_bytes", |b| {
        b.iter(|| Commitment::from_bytes(black_box(&cbytes)))
    });

    // MerkleProof (100 leaves, proof for index 0)
    let leaves: Vec<Hash> = (0..100).map(|i| hash_data(&(i as u32).to_le_bytes())).collect();
    let tree = MerkleTree::build(&leaves);
    let proof = tree.generate_proof(0).unwrap();

    group.bench_function("merkle_proof/to_bytes", |b| {
        b.iter(|| black_box(&proof).to_bytes())
    });

    let pbytes = proof.to_bytes();
    group.bench_function("merkle_proof/from_bytes", |b| {
        b.iter(|| MerkleProof::from_bytes(black_box(&pbytes)))
    });

    // DisputeProof
    let dp = DisputeProof {
        proof_type: ProofType::Mock,
        proof_bytes: vec![1, 2, 3, 4, 5],
        public_inputs: [0x2A; 32],
        input_hash: [0x01; 32],
        output_hash: [0x02; 32],
        wasm_hash: [0xCA; 32],
    };

    group.bench_function("dispute_proof/to_bytes", |b| {
        b.iter(|| black_box(&dp).to_bytes())
    });

    let dbytes = dp.to_bytes();
    group.bench_function("dispute_proof/from_bytes", |b| {
        b.iter(|| DisputeProof::from_bytes(black_box(&dbytes)))
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// End-to-end: full protocol (commit → prove all → verify all)
// ---------------------------------------------------------------------------

fn bench_end_to_end(c: &mut Criterion) {
    let mut group = c.benchmark_group("end_to_end");
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let wasm_hash = hash_data(b"counter_step_v1");

    for &n in &[32, 100, 1000] {
        group.bench_with_input(
            BenchmarkId::new("commit_sign", n),
            &n,
            |b, &n| {
                let (_, _, checkpoints) = build_checkpoints(n);
                b.iter(|| {
                    let (commitment, _tree) = create_commitment(black_box(&checkpoints), &wasm_hash);
                    sign_commitment(&commitment, &signing_key)
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("verify_all_proofs", n),
            &n,
            |b, &n| {
                let (_, _, checkpoints) = build_checkpoints(n);
                let (commitment, tree) = create_commitment(&checkpoints, &wasm_hash);
                b.iter(|| {
                    for i in 0..n as u64 {
                        let proof = tree.generate_proof(i).unwrap();
                        assert!(verify_proof(&proof));
                        assert_eq!(proof.root, commitment.root);
                    }
                })
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Register all benchmark groups
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_hash_primitives,
    bench_hash_chain,
    bench_merkle_build,
    bench_merkle_prove,
    bench_merkle_verify,
    bench_commitment,
    bench_transition,
    bench_fraud,
    bench_bisection,
    bench_zk_mock,
    bench_attestation,
    bench_serialization,
    bench_end_to_end,
);
criterion_main!(benches);
