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
