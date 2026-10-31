use sha2::{Sha256, Digest};
use ed25519_dalek::{Verifier, Signature, VerifyingKey};

#[derive(Debug, PartialEq)]
pub enum GateDecision {
    PermitAutonomous,
    EscalateToSigner { reason: String, payload_digest: [u8; 32] },
    HardReject(String),
}

pub struct BlastRadiusVector {
    pub read_volume: f32,   // 0.0 to 1.0 (Data exposure risk)
    pub write_scope: f32,   // 0.0 to 1.0 (State mutation / overwrite risk)
    pub financial_tier: f32,// 0.0 to 1.0 (Transaction or resource cost)
}

impl BlastRadiusVector {
    pub fn magnitude(&self) -> f32 {
        (self.read_volume.powi(2) + self.write_scope.powi(2) + self.financial_tier.powi(2)).sqrt()
    }
}

pub struct ExecutionGate {
    pub autonomous_ceiling: f32, // Maximum magnitude allowed without human sign-off
    pub partner_public_key: VerifyingKey,
}

impl ExecutionGate {
    pub fn evaluate_proposal(
        &self, 
        tool_name: &str, 
        raw_params: &str, 
        vector: &BlastRadiusVector
    ) -> GateDecision {
        // Step 1: Compute deterministic SHA-256 parameter digest
        let mut hasher = Sha256::new();
        hasher.update(tool_name.as_bytes());
        hasher.update(b":");
        hasher.update(raw_params.as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();

        // Step 2: Evaluate Euclidean Blast Radius
        let mag = vector.magnitude();
        if mag > self.autonomous_ceiling {
            return GateDecision::EscalateToSigner {
                reason: format!("Vector magnitude {:.3} exceeds threshold {:.3}", mag, self.autonomous_ceiling),
                payload_digest: digest,
            };
        }

        GateDecision::PermitAutonomous
    }

    pub fn verify_human_signature(
        &self, 
        digest: &[u8; 32], 
        signature: &Signature
    ) -> bool {
        self.partner_public_key.verify(digest, signature).is_ok()
    }
}

fn main() {
    println!("P.A.C.T. Execution Gate initialized.");
    println!("Ready to intercept and clamp agent tool payloads.");
}

// ==========================================
// P.A.C.T. SECURITY & VERIFICATION TEST SUITE
// ==========================================
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn setup_test_gate(ceiling: f32) -> (ExecutionGate, SigningKey) {
        // Deterministic 32-byte mock private key for local test execution
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let gate = ExecutionGate {
            autonomous_ceiling: ceiling,
            partner_public_key: verifying_key,
        };
        (gate, signing_key)
    }

    #[test]
    fn test_autonomous_execution_under_ceiling() {
        let (gate, _) = setup_test_gate(0.5);
        let safe_vector = BlastRadiusVector {
            read_volume: 0.1,
            write_scope: 0.1,
            financial_tier: 0.0,
        };

        // Magnitude is ~0.141, well under 0.5 ceiling
        let decision = gate.evaluate_proposal("read_file", "path=/tmp/test.log", &safe_vector);
        assert_eq!(decision, GateDecision::PermitAutonomous);
    }

    #[test]
    fn test_escalation_above_ceiling() {
        let (gate, _) = setup_test_gate(0.5);
        let risky_vector = BlastRadiusVector {
            read_volume: 0.6,
            write_scope: 0.8,
            financial_tier: 0.0,
        };

        // Magnitude is 1.0, breaches 0.5 ceiling
        let decision = gate.evaluate_proposal("drop_db_table", "table=users", &risky_vector);
        match decision {
            GateDecision::EscalateToSigner { reason, payload_digest } => {
                assert!(reason.contains("exceeds threshold"));
                assert_ne!(payload_digest, [0u8; 32]);
            }
            _ => panic!("Expected escalation to human signer"),
        }
    }

    #[test]
    fn test_valid_human_signature_verification() {
        let (gate, signing_key) = setup_test_gate(0.5);
        let digest = [42u8; 32];
        let valid_signature = signing_key.sign(&digest);

        let is_valid = gate.verify_human_signature(&digest, &valid_signature);
        assert!(is_valid, "Valid signature over digest must pass verification");
    }

    #[test]
    fn test_tampered_payload_rejected() {
        let (gate, signing_key) = setup_test_gate(0.5);
        let original_digest = [42u8; 32];
        let tampered_digest = [99u8; 32];

        // Sign the original digest, but pass the tampered digest to verify
        let signature = signing_key.sign(&original_digest);
        let is_valid = gate.verify_human_signature(&tampered_digest, &signature);
        assert!(!is_valid, "Signature over mismatched digest must be rejected");
    }
}
