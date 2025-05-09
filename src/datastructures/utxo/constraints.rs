use std::borrow::Borrow;

use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::{AllocVar, AllocationMode}, fields::fp::FpVar};
use ark_relations::r1cs::{Namespace, SynthesisError};

use super::UTXO;

#[derive(Debug)]
pub struct UTXOVar<F: PrimeField> {
    pub amount: FpVar<F>,
    pub id: FpVar<F>,
}

impl<F: PrimeField> AllocVar<UTXO, F> for UTXOVar<F> {
    fn new_variable<T: Borrow<UTXO>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let f = f()?;
        let UTXO { amount, id } = f.borrow();
        Ok(Self {
            amount: FpVar::new_variable(cs.clone(), || Ok(F::from(*amount)), mode)?,
            id: FpVar::new_variable(cs, || Ok(F::from(*id)), mode)?,
        })
    }
}
