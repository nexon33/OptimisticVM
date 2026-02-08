use crate::error::{OvpError, Result};
use crate::hash::hash_data;
use crate::transition::StepFunction;
use crate::types::{DisputeOutcome, Hash};

/// Phase of the bisection dispute protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BisectionPhase {
    WaitingDefenderMidpoint,
    WaitingChallengerChoice,
    WaitingDefenderProof,
    Resolved(DisputeOutcome),
}

/// Interactive bisection dispute narrowing a range to a single step.
#[derive(Clone, Debug)]
pub struct BisectionDispute {
    pub left_index: u64,
    pub right_index: u64,
    pub left_hash: Hash,
    pub right_hash: Hash,
    pub phase: BisectionPhase,
    pub rounds: u32,
    /// Midpoint index (valid when phase = WaitingChallengerChoice)
    midpoint_index: u64,
    midpoint_hash: Hash,
}

impl BisectionDispute {
    /// Create a new bisection dispute.
    ///
    /// - `left_hash` at `left_index` is agreed to be correct.
    /// - `right_hash` at `right_index` is claimed to be incorrect.
    pub fn new(
        left_index: u64,
        right_index: u64,
        left_hash: Hash,
        right_hash: Hash,
    ) -> Result<Self> {
        if right_index <= left_index {
            return Err(OvpError::InvalidProof(
                "right_index must be greater than left_index".to_string(),
            ));
        }
        Ok(Self {
            left_index,
            right_index,
            left_hash,
            right_hash,
            phase: BisectionPhase::WaitingDefenderMidpoint,
            rounds: 0,
            midpoint_index: 0,
            midpoint_hash: [0; 32],
        })
    }

    /// Defender reveals the hash at the midpoint.
    pub fn defender_reveal_midpoint(&mut self, midpoint_hash: Hash) -> Result<()> {
        if self.phase != BisectionPhase::WaitingDefenderMidpoint {
            return Err(OvpError::InvalidDisputePhase {
                expected: "WaitingDefenderMidpoint".to_string(),
                got: format!("{:?}", self.phase),
            });
        }

        self.midpoint_index = (self.left_index + self.right_index) / 2;
        self.midpoint_hash = midpoint_hash;
        self.phase = BisectionPhase::WaitingChallengerChoice;
        Ok(())
    }

    /// Challenger chooses which half contains the fraud.
    ///
    /// - `pick_right = true`: fraud is in [midpoint, right]
    /// - `pick_right = false`: fraud is in [left, midpoint]
    pub fn challenger_choose_half(&mut self, pick_right: bool) -> Result<()> {
        if self.phase != BisectionPhase::WaitingChallengerChoice {
            return Err(OvpError::InvalidDisputePhase {
                expected: "WaitingChallengerChoice".to_string(),
                got: format!("{:?}", self.phase),
            });
        }

        if pick_right {
            self.left_index = self.midpoint_index;
            self.left_hash = self.midpoint_hash;
        } else {
            self.right_index = self.midpoint_index;
            self.right_hash = self.midpoint_hash;
        }

        self.rounds += 1;

        if self.right_index - self.left_index == 1 {
            self.phase = BisectionPhase::WaitingDefenderProof;
        } else {
            self.phase = BisectionPhase::WaitingDefenderMidpoint;
        }

        Ok(())
    }

    /// Defender proves the single step [left_index → right_index].
    ///
    /// The defender provides the state at left_index and the inputs.
    /// Re-execution determines the outcome.
    pub fn defender_prove_step(
        &mut self,
        previous_state: &[u8],
        inputs: &[u8],
        step_fn: &dyn StepFunction,
    ) -> Result<DisputeOutcome> {
        if self.phase != BisectionPhase::WaitingDefenderProof {
            return Err(OvpError::InvalidDisputePhase {
                expected: "WaitingDefenderProof".to_string(),
                got: format!("{:?}", self.phase),
            });
        }

        // Step 2: Verify previous state matches left_hash
        let prev_hash = hash_data(previous_state);
        if prev_hash != self.left_hash {
            let outcome = DisputeOutcome::ChallengerWins {
                reason: "defender's state doesn't match agreed checkpoint".to_string(),
            };
            self.phase = BisectionPhase::Resolved(outcome.clone());
            return Ok(outcome);
        }

        // Step 3: Re-execute
        let computed_output = step_fn.execute(previous_state, inputs);
        let computed_hash = hash_data(&computed_output);

        // Step 4: Compare
        let outcome = if computed_hash == self.right_hash {
            DisputeOutcome::DefenderWins
        } else {
            DisputeOutcome::ChallengerWins {
                reason: "step execution mismatch: fraud confirmed".to_string(),
            }
        };

        self.phase = BisectionPhase::Resolved(outcome.clone());
        Ok(outcome)
    }

    /// Resolve by timeout. The non-responding party loses.
    pub fn resolve_timeout(&mut self, defender_timed_out: bool) -> DisputeOutcome {
        let outcome = if defender_timed_out {
            DisputeOutcome::ChallengerWins {
                reason: "defender timed out".to_string(),
            }
        } else {
            DisputeOutcome::DefenderWins
        };
        self.phase = BisectionPhase::Resolved(outcome.clone());
        outcome
    }

    /// Current range width.
    pub fn range_width(&self) -> u64 {
        self.right_index - self.left_index
    }

    /// Whether the dispute has been resolved.
    pub fn is_resolved(&self) -> bool {
        matches!(self.phase, BisectionPhase::Resolved(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash_data;

    fn increment_step(state: &[u8], _inputs: &[u8]) -> Vec<u8> {
        let mut out = state.to_vec();
        for b in &mut out {
            *b = b.wrapping_add(1);
        }
        out
    }

    /// Build honest checkpoint hashes for 8 steps.
    fn build_honest_hashes(initial_state: &[u8]) -> (Vec<Hash>, Vec<Vec<u8>>) {
        let mut states = vec![initial_state.to_vec()];
        let mut hashes = vec![hash_data(initial_state)];

        for _ in 0..8 {
            let prev = states.last().unwrap();
            let next = increment_step(prev, &[]);
            hashes.push(hash_data(&next));
            states.push(next);
        }

        (hashes, states)
    }

    #[test]
    fn test_bisection_full_honest_defender() {
        let initial = vec![0x00u8; 4];
        let (hashes, states) = build_honest_hashes(&initial);

        // Dispute range [0, 8]
        let mut dispute =
            BisectionDispute::new(0, 8, hashes[0], hashes[8]).unwrap();

        // Bisect: midpoint = 4, challenger picks right [4, 8]
        dispute.defender_reveal_midpoint(hashes[4]).unwrap();
        dispute.challenger_choose_half(true).unwrap(); // [4, 8]

        // Bisect: midpoint = 6, challenger picks left [4, 6]
        dispute.defender_reveal_midpoint(hashes[6]).unwrap();
        dispute.challenger_choose_half(false).unwrap(); // [4, 6]

        // Bisect: midpoint = 5, challenger picks right [5, 6]
        dispute.defender_reveal_midpoint(hashes[5]).unwrap();
        dispute.challenger_choose_half(true).unwrap(); // [5, 6], range = 1

        assert_eq!(dispute.phase, BisectionPhase::WaitingDefenderProof);

        // Defender proves step 5 → 6
        let outcome = dispute
            .defender_prove_step(&states[5], &[], &increment_step)
            .unwrap();

        assert_eq!(outcome, DisputeOutcome::DefenderWins);
    }

    #[test]
    fn test_bisection_fraudulent_defender() {
        let initial = vec![0x00u8; 4];
        let (mut hashes, states) = build_honest_hashes(&initial);

        // Corrupt hash at index 6
        hashes[6] = hash_data(b"fraudulent_state");

        let mut dispute =
            BisectionDispute::new(0, 8, hashes[0], hashes[8]).unwrap();

        // Bisect to [5, 6] where fraud lives
        dispute.defender_reveal_midpoint(hashes[4]).unwrap();
        dispute.challenger_choose_half(true).unwrap(); // [4, 8]

        dispute.defender_reveal_midpoint(hashes[6]).unwrap();
        dispute.challenger_choose_half(false).unwrap(); // [4, 6]

        dispute.defender_reveal_midpoint(hashes[5]).unwrap();
        dispute.challenger_choose_half(true).unwrap(); // [5, 6], range = 1

        // Defender tries to prove step 5 → 6
        // But hashes[6] was corrupted, so re-execution won't match
        let outcome = dispute
            .defender_prove_step(&states[5], &[], &increment_step)
            .unwrap();

        match outcome {
            DisputeOutcome::ChallengerWins { reason } => {
                assert!(reason.contains("mismatch"));
            }
            DisputeOutcome::DefenderWins => panic!("defender should not win"),
        }
    }

    #[test]
    fn test_bisection_timeout() {
        let mut dispute = BisectionDispute::new(
            0,
            8,
            hash_data(b"left"),
            hash_data(b"right"),
        )
        .unwrap();

        let outcome = dispute.resolve_timeout(true); // defender timed out
        assert!(matches!(outcome, DisputeOutcome::ChallengerWins { .. }));
        assert!(dispute.is_resolved());
    }

    #[test]
    fn test_bisection_challenger_timeout() {
        let mut dispute = BisectionDispute::new(
            0,
            8,
            hash_data(b"left"),
            hash_data(b"right"),
        )
        .unwrap();

        let outcome = dispute.resolve_timeout(false); // challenger timed out
        assert_eq!(outcome, DisputeOutcome::DefenderWins);
    }

    #[test]
    fn test_bisection_wrong_phase() {
        let mut dispute = BisectionDispute::new(
            0,
            8,
            hash_data(b"left"),
            hash_data(b"right"),
        )
        .unwrap();

        // Can't choose half before midpoint is revealed
        assert!(dispute.challenger_choose_half(true).is_err());
    }

    #[test]
    fn test_bisection_defender_lies_about_state() {
        let initial = vec![0x00u8; 4];
        let (hashes, _states) = build_honest_hashes(&initial);

        let mut dispute =
            BisectionDispute::new(0, 2, hashes[0], hashes[2]).unwrap();

        dispute.defender_reveal_midpoint(hashes[1]).unwrap();
        dispute.challenger_choose_half(true).unwrap(); // [1, 2]

        // Defender provides wrong previous state
        let wrong_state = vec![0xFF; 4];
        let outcome = dispute
            .defender_prove_step(&wrong_state, &[], &increment_step)
            .unwrap();

        match outcome {
            DisputeOutcome::ChallengerWins { reason } => {
                assert!(reason.contains("doesn't match"));
            }
            _ => panic!("challenger should win"),
        }
    }
}
