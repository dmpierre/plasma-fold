use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::{
        poseidon::constraints::{CRHGadget, CRHParametersVar},
        CRHSchemeGadget,
    },
    sponge::{constraints::AbsorbGadget, Absorb},
};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;

use crate::datastructures::transaction::constraints::TransactionVar;

use super::TransactionCRH;

pub struct TransactionVarCRH<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> CRHSchemeGadget<TransactionCRH<F>, F> for TransactionVarCRH<F> {
    type InputVar = TransactionVar<F>;
    type OutputVar = FpVar<F>;
    type ParametersVar = CRHParametersVar<F>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        let elements = input.to_sponge_field_elements()?;
        Ok(CRHGadget::evaluate(parameters, &elements)?)
    }
}
