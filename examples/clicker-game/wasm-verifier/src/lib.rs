use ovp::commitment::create_commitment;
use ovp::fraud::generate_fraud_proof;
use ovp::hash::{hash_data, hash_transition};
use ovp::types::FraudResult;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// Game State: 32 bytes, fixed-size little-endian binary
//   Offset 0:  gold            (u64 LE)
//   Offset 8:  click_power     (u64 LE)
//   Offset 16: upgrade_level_0 (u64 LE)  "Better Pickaxe"
//   Offset 24: upgrade_level_1 (u64 LE)  "Gold Rush"
// ---------------------------------------------------------------------------

const STATE_SIZE: usize = 32;
const ACTION_SIZE: usize = 9;
const MAX_UPGRADE_LEVEL: u64 = 62;

#[derive(Clone, Debug, PartialEq, Eq)]
struct GameState {
    gold: u64,
    click_power: u64,
    upgrade_level_0: u64,
    upgrade_level_1: u64,
}

impl GameState {
    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() != STATE_SIZE {
            return None;
        }
        Some(Self {
            gold: u64::from_le_bytes(data[0..8].try_into().unwrap()),
            click_power: u64::from_le_bytes(data[8..16].try_into().unwrap()),
            upgrade_level_0: u64::from_le_bytes(data[16..24].try_into().unwrap()),
            upgrade_level_1: u64::from_le_bytes(data[24..32].try_into().unwrap()),
        })
    }

    fn to_bytes(&self) -> [u8; STATE_SIZE] {
        let mut buf = [0u8; STATE_SIZE];
        buf[0..8].copy_from_slice(&self.gold.to_le_bytes());
        buf[8..16].copy_from_slice(&self.click_power.to_le_bytes());
        buf[16..24].copy_from_slice(&self.upgrade_level_0.to_le_bytes());
        buf[24..32].copy_from_slice(&self.upgrade_level_1.to_le_bytes());
        buf
    }

    fn apply(&mut self, action: &Action) {
        match action {
            Action::Click => {
                self.gold = self.gold.saturating_add(self.click_power);
            }
            Action::BuyUpgrade(0) => {
                if self.upgrade_level_0 >= MAX_UPGRADE_LEVEL {
                    return;
                }
                let cost = 10u64.saturating_mul(1u64 << self.upgrade_level_0);
                if self.gold >= cost {
                    self.gold -= cost;
                    self.click_power = self.click_power.saturating_add(1);
                    self.upgrade_level_0 += 1;
                }
            }
            Action::BuyUpgrade(1) => {
                if self.upgrade_level_1 >= MAX_UPGRADE_LEVEL {
                    return;
                }
                let cost = 50u64.saturating_mul(1u64 << self.upgrade_level_1);
                if self.gold >= cost {
                    self.gold -= cost;
                    self.click_power = self.click_power.saturating_mul(2);
                    self.upgrade_level_1 += 1;
                }
            }
            Action::BuyUpgrade(_) => {} // unknown upgrade — no-op
        }
    }
}

// ---------------------------------------------------------------------------
// Action: 9 bytes
//   Offset 0: type   (u8)  0x00=Click, 0x01=BuyUpgrade
//   Offset 1: id     (u64 LE, only meaningful for BuyUpgrade)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
enum Action {
    Click,
    BuyUpgrade(u64),
}

impl Action {
    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() != ACTION_SIZE {
            return None;
        }
        match data[0] {
            0x00 => Some(Action::Click),
            0x01 => {
                let id = u64::from_le_bytes(data[1..9].try_into().unwrap());
                Some(Action::BuyUpgrade(id))
            }
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Canonical step function (used by both WASM export and OVP fraud proofs)
// ---------------------------------------------------------------------------

fn canonical_step(state_bytes: &[u8], action_bytes: &[u8]) -> Vec<u8> {
    let mut state = match GameState::from_bytes(state_bytes) {
        Some(s) => s,
        None => return state_bytes.to_vec(), // malformed → unchanged
    };
    if let Some(action) = Action::from_bytes(action_bytes) {
        state.apply(&action);
    }
    state.to_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// WASM exports
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn initial_state() -> Vec<u8> {
    let state = GameState {
        gold: 0,
        click_power: 1,
        upgrade_level_0: 0,
        upgrade_level_1: 0,
    };
    state.to_bytes().to_vec()
}

#[wasm_bindgen]
pub fn game_step(state: &[u8], action: &[u8]) -> Vec<u8> {
    canonical_step(state, action)
}

#[wasm_bindgen]
pub fn hash_state(data: &[u8]) -> Vec<u8> {
    hash_data(data).to_vec()
}

// ---------------------------------------------------------------------------
// Batch verification with OVP fraud proof generation
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct Transition {
    prev_state: String,
    action: String,
    claimed_state: String,
}

#[derive(Deserialize)]
struct BatchRequest {
    transitions: Vec<Transition>,
}

#[derive(Serialize, Deserialize)]
struct BatchResult {
    valid: bool,
    fraud_index: Option<usize>,
    detail: Option<String>,
    fraud_proof: Option<FraudProofJson>,
}

#[derive(Serialize, Deserialize)]
struct FraudProofJson {
    commitment_root: String,
    checkpoint_index: u64,
    claimed_hash: String,
    computed_hash: String,
    merkle_proof_leaf: String,
    merkle_proof_root: String,
    merkle_proof_siblings: Vec<String>,
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[wasm_bindgen]
pub fn verify_batch(batch_json: &str) -> String {
    let batch: BatchRequest = match serde_json::from_str(batch_json) {
        Ok(b) => b,
        Err(e) => {
            return serde_json::to_string(&BatchResult {
                valid: false,
                fraud_index: None,
                detail: Some(format!("Invalid JSON: {}", e)),
                fraud_proof: None,
            })
            .unwrap();
        }
    };

    // First pass: find the fraudulent transition by re-executing each step
    let mut fraud_idx = None;
    let mut server_computed = Vec::new();
    let mut detail_msg = String::new();

    for (i, t) in batch.transitions.iter().enumerate() {
        let prev = match hex_decode(&t.prev_state) {
            Some(v) if v.len() == STATE_SIZE => v,
            _ => {
                return error_result(&format!("Transition {}: invalid prev_state hex", i));
            }
        };
        let action = match hex_decode(&t.action) {
            Some(v) if v.len() == ACTION_SIZE => v,
            _ => {
                return error_result(&format!("Transition {}: invalid action hex", i));
            }
        };
        let claimed = match hex_decode(&t.claimed_state) {
            Some(v) if v.len() == STATE_SIZE => v,
            _ => {
                return error_result(&format!(
                    "Transition {}: invalid claimed_state hex",
                    i
                ));
            }
        };

        let computed = canonical_step(&prev, &action);
        server_computed.push(computed.clone());

        if computed != claimed && fraud_idx.is_none() {
            let server_state = GameState::from_bytes(&computed).unwrap();
            let client_state = GameState::from_bytes(&claimed).unwrap();
            detail_msg = format!(
                "Step {}: server computed gold={}, click_power={}, upgrades=[{}, {}]; \
                 client claimed gold={}, click_power={}, upgrades=[{}, {}]",
                i,
                server_state.gold,
                server_state.click_power,
                server_state.upgrade_level_0,
                server_state.upgrade_level_1,
                client_state.gold,
                client_state.click_power,
                client_state.upgrade_level_0,
                client_state.upgrade_level_1,
            );
            fraud_idx = Some(i);
        }
    }

    if fraud_idx.is_none() {
        return serde_json::to_string(&BatchResult {
            valid: true,
            fraud_index: None,
            detail: None,
            fraud_proof: None,
        })
        .unwrap();
    }

    let fraud_i = fraud_idx.unwrap();

    // Build OVP checkpoint hashes for the entire batch
    let mut checkpoints = Vec::with_capacity(batch.transitions.len());
    for t in &batch.transitions {
        let prev_bytes = hex_decode(&t.prev_state).unwrap();
        let action_bytes = hex_decode(&t.action).unwrap();
        let claimed_bytes = hex_decode(&t.claimed_state).unwrap();
        let prev_hash = hash_data(&prev_bytes);
        let input_hash = hash_data(&action_bytes);
        let claimed_hash = hash_data(&claimed_bytes);
        checkpoints.push(hash_transition(&prev_hash, &input_hash, &claimed_hash));
    }

    let wasm_hash = hash_data(b"clicker-verifier-v1");
    let (commitment, tree) = create_commitment(&checkpoints, &wasm_hash);

    let merkle_proof = match tree.generate_proof(fraud_i as u64, &wasm_hash) {
        Ok(p) => p,
        Err(e) => {
            return error_result(&format!("Merkle proof generation failed: {}", e));
        }
    };

    let prev_bytes = hex_decode(&batch.transitions[fraud_i].prev_state).unwrap();
    let action_bytes = hex_decode(&batch.transitions[fraud_i].action).unwrap();

    let fraud_result = generate_fraud_proof(
        &commitment,
        fraud_i as u64,
        &prev_bytes,
        &action_bytes,
        merkle_proof,
        &canonical_step,
        b"ovp-anticheat-server",
    );

    match fraud_result {
        Ok(FraudResult::FraudConfirmed(fp)) => {
            let proof_json = FraudProofJson {
                commitment_root: hex_encode(&fp.commitment_root),
                checkpoint_index: fp.checkpoint_index,
                claimed_hash: hex_encode(&fp.claimed_hash),
                computed_hash: hex_encode(&fp.computed_hash),
                merkle_proof_leaf: hex_encode(&fp.merkle_proof.leaf),
                merkle_proof_root: hex_encode(&fp.merkle_proof.root),
                merkle_proof_siblings: fp
                    .merkle_proof
                    .siblings
                    .iter()
                    .map(|s| hex_encode(&s.hash))
                    .collect(),
            };
            serde_json::to_string(&BatchResult {
                valid: false,
                fraud_index: Some(fraud_i),
                detail: Some(detail_msg),
                fraud_proof: Some(proof_json),
            })
            .unwrap()
        }
        Ok(FraudResult::NoFraud { .. }) => {
            // Shouldn't happen since we already detected a mismatch, but handle gracefully
            serde_json::to_string(&BatchResult {
                valid: false,
                fraud_index: Some(fraud_i),
                detail: Some(detail_msg),
                fraud_proof: None,
            })
            .unwrap()
        }
        Err(e) => error_result(&format!("Fraud proof generation error: {}", e)),
    }
}

fn error_result(msg: &str) -> String {
    serde_json::to_string(&BatchResult {
        valid: false,
        fraud_index: None,
        detail: Some(msg.to_string()),
        fraud_proof: None,
    })
    .unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn init() -> GameState {
        GameState {
            gold: 0,
            click_power: 1,
            upgrade_level_0: 0,
            upgrade_level_1: 0,
        }
    }

    #[test]
    fn test_initial_state_bytes() {
        let bytes = initial_state();
        assert_eq!(bytes.len(), 32);
        let state = GameState::from_bytes(&bytes).unwrap();
        assert_eq!(state.gold, 0);
        assert_eq!(state.click_power, 1);
        assert_eq!(state.upgrade_level_0, 0);
        assert_eq!(state.upgrade_level_1, 0);
    }

    #[test]
    fn test_click_adds_gold() {
        let mut state = init();
        state.apply(&Action::Click);
        assert_eq!(state.gold, 1);
        assert_eq!(state.click_power, 1);
    }

    #[test]
    fn test_click_respects_click_power() {
        let mut state = init();
        state.click_power = 10;
        state.apply(&Action::Click);
        assert_eq!(state.gold, 10);
    }

    #[test]
    fn test_buy_upgrade_0_pickaxe() {
        let mut state = init();
        state.gold = 10;
        state.apply(&Action::BuyUpgrade(0));
        assert_eq!(state.gold, 0);
        assert_eq!(state.click_power, 2);
        assert_eq!(state.upgrade_level_0, 1);
    }

    #[test]
    fn test_buy_upgrade_0_insufficient_gold() {
        let mut state = init();
        state.gold = 5;
        let original = state.clone();
        state.apply(&Action::BuyUpgrade(0));
        assert_eq!(state, original);
    }

    #[test]
    fn test_buy_upgrade_0_scaling_cost() {
        let mut state = init();
        state.gold = 1000;
        // Level 0 → 1: costs 10
        state.apply(&Action::BuyUpgrade(0));
        assert_eq!(state.gold, 990);
        assert_eq!(state.upgrade_level_0, 1);
        // Level 1 → 2: costs 20
        state.apply(&Action::BuyUpgrade(0));
        assert_eq!(state.gold, 970);
        assert_eq!(state.upgrade_level_0, 2);
        // Level 2 → 3: costs 40
        state.apply(&Action::BuyUpgrade(0));
        assert_eq!(state.gold, 930);
        assert_eq!(state.upgrade_level_0, 3);
    }

    #[test]
    fn test_buy_upgrade_1_gold_rush() {
        let mut state = init();
        state.gold = 50;
        state.apply(&Action::BuyUpgrade(1));
        assert_eq!(state.gold, 0);
        assert_eq!(state.click_power, 2); // 1 * 2
        assert_eq!(state.upgrade_level_1, 1);
    }

    #[test]
    fn test_buy_upgrade_1_doubles_power() {
        let mut state = init();
        state.gold = 200;
        state.click_power = 4;
        state.apply(&Action::BuyUpgrade(1));
        assert_eq!(state.click_power, 8); // 4 * 2
    }

    #[test]
    fn test_buy_upgrade_1_insufficient_gold() {
        let mut state = init();
        state.gold = 30;
        let original = state.clone();
        state.apply(&Action::BuyUpgrade(1));
        assert_eq!(state, original);
    }

    #[test]
    fn test_upgrade_level_cap() {
        let mut state = init();
        state.gold = u64::MAX;
        state.upgrade_level_0 = MAX_UPGRADE_LEVEL;
        let original = state.clone();
        state.apply(&Action::BuyUpgrade(0));
        assert_eq!(state, original); // no-op at cap
    }

    #[test]
    fn test_unknown_upgrade_noop() {
        let mut state = init();
        state.gold = 1000;
        let original = state.clone();
        state.apply(&Action::BuyUpgrade(99));
        assert_eq!(state, original);
    }

    #[test]
    fn test_roundtrip_bytes() {
        let state = GameState {
            gold: 12345,
            click_power: 42,
            upgrade_level_0: 3,
            upgrade_level_1: 1,
        };
        let bytes = state.to_bytes();
        let recovered = GameState::from_bytes(&bytes).unwrap();
        assert_eq!(state, recovered);
    }

    #[test]
    fn test_action_from_bytes_click() {
        let mut buf = [0u8; ACTION_SIZE];
        buf[0] = 0x00;
        assert_eq!(Action::from_bytes(&buf), Some(Action::Click));
    }

    #[test]
    fn test_action_from_bytes_upgrade() {
        let mut buf = [0u8; ACTION_SIZE];
        buf[0] = 0x01;
        buf[1..9].copy_from_slice(&1u64.to_le_bytes());
        assert_eq!(Action::from_bytes(&buf), Some(Action::BuyUpgrade(1)));
    }

    #[test]
    fn test_game_step_wasm_export() {
        let state = initial_state();
        let mut action = [0u8; 9];
        action[0] = 0x00; // Click
        let next = game_step(&state, &action);
        let gs = GameState::from_bytes(&next).unwrap();
        assert_eq!(gs.gold, 1);
    }

    #[test]
    fn test_verify_batch_all_honest() {
        let s0 = initial_state();
        let mut action_click = [0u8; 9];
        action_click[0] = 0x00;

        let s1 = game_step(&s0, &action_click);
        let s2 = game_step(&s1, &action_click);

        let batch = format!(
            r#"{{"transitions":[
                {{"prev_state":"{}","action":"{}","claimed_state":"{}"}},
                {{"prev_state":"{}","action":"{}","claimed_state":"{}"}}
            ]}}"#,
            hex_encode(&s0),
            hex_encode(&action_click),
            hex_encode(&s1),
            hex_encode(&s1),
            hex_encode(&action_click),
            hex_encode(&s2),
        );
        let result = verify_batch(&batch);
        let parsed: BatchResult = serde_json::from_str(&result).unwrap();
        assert!(parsed.valid);
        assert!(parsed.fraud_index.is_none());
    }

    #[test]
    fn test_verify_batch_detects_fraud() {
        let s0 = initial_state();
        let mut action_click = [0u8; 9];
        action_click[0] = 0x00;

        let s1 = game_step(&s0, &action_click);

        // Tamper: claim gold = 999999
        let mut fake_s1 = s1.clone();
        fake_s1[0..8].copy_from_slice(&999999u64.to_le_bytes());

        let batch = format!(
            r#"{{"transitions":[
                {{"prev_state":"{}","action":"{}","claimed_state":"{}"}}
            ]}}"#,
            hex_encode(&s0),
            hex_encode(&action_click),
            hex_encode(&fake_s1),
        );
        let result = verify_batch(&batch);
        let parsed: BatchResult = serde_json::from_str(&result).unwrap();
        assert!(!parsed.valid);
        assert_eq!(parsed.fraud_index, Some(0));
        assert!(parsed.fraud_proof.is_some());
        let fp = parsed.fraud_proof.unwrap();
        assert_ne!(fp.claimed_hash, fp.computed_hash);
    }

    #[test]
    fn test_gold_saturation() {
        let mut state = init();
        state.gold = u64::MAX - 5;
        state.click_power = 10;
        state.apply(&Action::Click);
        assert_eq!(state.gold, u64::MAX); // saturating_add
    }
}
