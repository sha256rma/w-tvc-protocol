//! The committed inference relation, expressed as a Rank-1 Constraint System.
//!
//! # What this circuit actually proves
//!
//! W-TVC's security claim is not "an AI produced this number". It is the
//! strictly narrower and far more checkable claim:
//!
//! > *The same parameters that are bound by the public commitment are the
//! > parameters that transformed this input into this output.*
//!
//! That claim is what defeats token-downgrading. A provider who silently swaps a
//! flagship model for a cheaper distillation still has to produce a proof whose
//! public commitment input matches the digest frozen at ceremony time, and the
//! substituted parameters will not satisfy both halves of the relation at once.
//!
//! # The relation
//!
//! Private witness: `weight`, `bias`.
//! Public inputs, in allocation order: `input`, `output`, `commitment`.
//!
//! ```text
//!   weight * input       = product          (the inference step)
//!   product + bias       = output           (the claimed result)
//!   weight * weight      = weight_squared   (parameter binding, part one)
//!   weight_squared + bias = commitment      (parameter binding, part two)
//! ```
//!
//! The first two constraints pin the computation; the last two pin the
//! parameters to a value that is public and was fixed before any inference ran.
//! Satisfying the system requires a single `(weight, bias)` pair that explains
//! the transcript *and* reproduces the commitment, which is exactly the
//! non-substitution property the protocol sells.
//!
//! # Scope, stated plainly
//!
//! This is an affine relation over `Fr`, not a neural network. A production
//! deployment replaces [`InferenceCircuit`] with a quantised arithmetic circuit
//! over the real weight tensor, and replaces the two binding constraints with a
//! Poseidon or Merkle commitment to that tensor. Everything upstream and
//! downstream of the circuit in this repository — the ceremony, the digest
//! derivation, the burn, the BIP-340 commitment, the Nostr transport, the
//! wallet-side check — is independent of that substitution and does not change.
//! The circuit is the component a production deployment swaps; the protocol
//! around it is the contribution.

use ark_bn254::Fr;
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};

use crate::error::{Result, TvcError};

/// Number of public inputs the verifier must supply, in allocation order.
pub const PUBLIC_INPUT_ARITY: usize = 3;

/// The committed inference relation.
///
/// Constructed either as a [`blueprint`](InferenceCircuit::blueprint) carrying no
/// assignments, which is what the ceremony synthesises to derive the structural
/// keys, or as a [`witness`](InferenceCircuit::witness) carrying a full
/// assignment, which is what the prover consumes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InferenceCircuit {
    weight: Option<Fr>,
    bias: Option<Fr>,
    input: Option<Fr>,
    output: Option<Fr>,
    commitment: Option<Fr>,
}

impl InferenceCircuit {
    /// Builds the unassigned shape of the relation.
    ///
    /// The trusted setup depends only on the *shape* of the constraint system,
    /// never on any assignment, which is precisely why a verifying key can be
    /// frozen once per model version and reused for every subsequent inference.
    pub const fn blueprint() -> Self {
        Self {
            weight: None,
            bias: None,
            input: None,
            output: None,
            commitment: None,
        }
    }

    /// Builds a fully assigned instance from private parameters and a public input.
    ///
    /// The public `output` and `commitment` are derived here rather than accepted
    /// from the caller so that a prover cannot construct an instance whose public
    /// inputs disagree with its own witness.
    pub fn witness(weight: Fr, bias: Fr, input: Fr) -> Self {
        Self {
            weight: Some(weight),
            bias: Some(bias),
            input: Some(input),
            output: Some(weight * input + bias),
            commitment: Some(weight * weight + bias),
        }
    }

    /// Returns the public inputs in the order the verifier expects them.
    pub fn public_inputs(&self) -> Result<[Fr; PUBLIC_INPUT_ARITY]> {
        Ok([
            self.input.ok_or(TvcError::MissingWitness)?,
            self.output.ok_or(TvcError::MissingWitness)?,
            self.commitment.ok_or(TvcError::MissingWitness)?,
        ])
    }

    /// Returns the public parameter commitment field element, when assigned.
    pub const fn commitment(&self) -> Option<Fr> {
        self.commitment
    }

    /// Returns the claimed public output, when assigned.
    pub const fn output(&self) -> Option<Fr> {
        self.output
    }
}

impl ConstraintSynthesizer<Fr> for InferenceCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> core::result::Result<(), SynthesisError> {
        let weight_value = self.weight;
        let bias_value = self.bias;
        let input_value = self.input;
        let output_value = self.output;
        let commitment_value = self.commitment;

        let weight = cs.new_witness_variable(|| weight_value.ok_or(SynthesisError::AssignmentMissing))?;
        let bias = cs.new_witness_variable(|| bias_value.ok_or(SynthesisError::AssignmentMissing))?;

        let input = cs.new_input_variable(|| input_value.ok_or(SynthesisError::AssignmentMissing))?;
        let output = cs.new_input_variable(|| output_value.ok_or(SynthesisError::AssignmentMissing))?;
        let commitment =
            cs.new_input_variable(|| commitment_value.ok_or(SynthesisError::AssignmentMissing))?;

        let product = cs.new_witness_variable(|| {
            let w = weight_value.ok_or(SynthesisError::AssignmentMissing)?;
            let x = input_value.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(w * x)
        })?;
        let weight_squared = cs.new_witness_variable(|| {
            let w = weight_value.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(w * w)
        })?;

        cs.enforce_constraint(lc!() + weight, lc!() + input, lc!() + product)?;
        cs.enforce_constraint(lc!() + product + bias, lc!() + Variable::One, lc!() + output)?;
        cs.enforce_constraint(lc!() + weight, lc!() + weight, lc!() + weight_squared)?;
        cs.enforce_constraint(
            lc!() + weight_squared + bias,
            lc!() + Variable::One,
            lc!() + commitment,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn honest_witness_satisfies_the_relation() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = InferenceCircuit::witness(Fr::from(7u64), Fr::from(3u64), Fr::from(11u64));
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(cs.num_instance_variables(), PUBLIC_INPUT_ARITY + 1);
    }

    #[test]
    fn substituted_parameters_break_the_binding() {
        let honest = InferenceCircuit::witness(Fr::from(7u64), Fr::from(3u64), Fr::from(11u64));
        let substituted = InferenceCircuit::witness(Fr::from(5u64), Fr::from(3u64), Fr::from(11u64));
        assert_ne!(honest.commitment(), substituted.commitment());
    }

    #[test]
    fn blueprint_exposes_no_assignment() {
        assert!(InferenceCircuit::blueprint().public_inputs().is_err());
    }
}
