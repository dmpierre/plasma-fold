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

use crate::datastructures::{
    noncemap::constraints::NonceVar, transaction::constraints::TransactionVar,
};

use super::{NonceCRH, TransactionCRH};

pub struct TransactionVarCRH<F: PrimeField> {
    _f: PhantomData<F>,
}

pub struct NonceVarCRH<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField> TransactionVarCRH<F> {
    pub fn new() -> Self {
        Self { _f: PhantomData }
    }
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

impl<F: PrimeField + Absorb> CRHSchemeGadget<NonceCRH<F>, F> for NonceVarCRH<F> {
    type InputVar = [NonceVar<F>];
    type OutputVar = FpVar<F>;
    type ParametersVar = CRHParametersVar<F>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        Ok(CRHGadget::evaluate(parameters, input)?)
    }
}
