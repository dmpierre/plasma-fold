use std::{borrow::Borrow, marker::PhantomData};

use ark_crypto_primitives::{
    crh::poseidon::constraints::TwoToOneCRHGadget,
    merkle_tree::{constraints::ConfigGadget, IdentityDigestConverter},
    sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
};
use ark_relations::r1cs::{Namespace, SynthesisError};

use crate::primitives::crh::constraints::UTXOVarCRH;

use super::{UTXOTreeConfig, UTXO};

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

pub struct UTXOTreeConfigGadget<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> ConfigGadget<UTXOTreeConfig<F>, F> for UTXOTreeConfigGadget<F> {
    type Leaf = UTXOVar<F>;
    type LeafDigest = FpVar<F>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<F>>;
    type InnerDigest = FpVar<F>;
    type LeafHash = UTXOVarCRH<F>;
    type TwoToOneHash = TwoToOneCRHGadget<F>;
}
