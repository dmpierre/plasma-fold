use std::{borrow::Borrow, marker::PhantomData};

use ark_crypto_primitives::{
    crh::poseidon::constraints::TwoToOneCRHGadget,
    merkle_tree::{constraints::ConfigGadget, IdentityDigestConverter},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
    groups::CurveVar,
    prelude::Boolean,
};
use ark_relations::gr1cs::{Namespace, SynthesisError};

use crate::{
    datastructures::keypair::constraints::PublicKeyVar,
    primitives::{crh::constraints::UTXOVarCRH, sparsemt::constraints::SparseConfigGadget},
};

use super::{UTXOTreeConfig, UTXO};

#[derive(Clone, Debug)]
pub struct UTXOVar<F: PrimeField + Absorb, C: CurveGroup<BaseField = F>, CVar: CurveVar<C, F>> {
    pub amount: FpVar<F>,
    pub pk: PublicKeyVar<C, CVar>,
    pub is_dummy: Boolean<F>,
}

impl<F: PrimeField + Absorb, C: CurveGroup<BaseField = F>, CVar: CurveVar<C, F>>
    AllocVar<UTXO<C>, F> for UTXOVar<F, C, CVar>
{
    fn new_variable<T: Borrow<UTXO<C>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let f = f()?;
        let UTXO {
            amount,
            pk,
            is_dummy,
        } = f.borrow();
        Ok(Self {
            amount: FpVar::new_variable(cs.clone(), || Ok(F::from(*amount)), mode)?,
            pk: PublicKeyVar::new_variable(cs.clone(), || Ok(*pk), mode)?,
            is_dummy: Boolean::new_variable(cs, || Ok(is_dummy), mode)?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct UTXOTreeConfigGadget<F: PrimeField + Absorb, C: CurveGroup, CVar: CurveVar<C, F>> {
    _f: PhantomData<F>,
    _c: PhantomData<C>,
    _cvar: PhantomData<CVar>,
}

impl<F: PrimeField + Absorb, C: CurveGroup<BaseField = F>, CVar: CurveVar<C, F>>
    ConfigGadget<UTXOTreeConfig<C>, F> for UTXOTreeConfigGadget<F, C, CVar>
{
    type Leaf = UTXOVar<F, C, CVar>;
    type LeafDigest = FpVar<F>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<F>>;
    type InnerDigest = FpVar<F>;
    type LeafHash = UTXOVarCRH<F, C, CVar>;
    type TwoToOneHash = TwoToOneCRHGadget<F>;
}

impl<F: PrimeField + Absorb, C: CurveGroup<BaseField = F>, CVar: CurveVar<C, F>>
    SparseConfigGadget<UTXOTreeConfig<C>, F> for UTXOTreeConfigGadget<F, C, CVar>
{
    const HEIGHT: u64 = 32;
}
