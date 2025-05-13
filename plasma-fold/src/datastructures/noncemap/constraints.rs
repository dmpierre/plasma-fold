use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::poseidon::constraints::TwoToOneCRHGadget,
    merkle_tree::{
        constraints::{ConfigGadget, PathVar},
        Config, IdentityDigestConverter,
    },
    sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, prelude::Boolean};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crate::primitives::crh::constraints::NonceVarCRH;

use super::NonceTreeConfig;

pub type NonceVar<F> = FpVar<F>;
pub struct NonceTreeConfigGadget<P: Config, F: PrimeField> {
    _f: PhantomData<P>,
    _f1: PhantomData<F>,
}

impl<P: Config, F: PrimeField + Absorb> ConfigGadget<NonceTreeConfig<F>, F>
    for NonceTreeConfigGadget<P, F>
{
    type Leaf = [NonceVar<F>];
    type LeafDigest = FpVar<F>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<F>>;
    type InnerDigest = FpVar<F>;
    type LeafHash = NonceVarCRH<F>;
    type TwoToOneHash = TwoToOneCRHGadget<F>;
}

pub struct NonceTreeGadgets<P: Config, F: PrimeField, PG: ConfigGadget<P, F>> {
    _f: PhantomData<P>,
    _f1: PhantomData<F>,
    _f2: PhantomData<PG>,
}

impl<P: Config, F: PrimeField, PG: ConfigGadget<P, F>> NonceTreeGadgets<P, F, PG> {
    pub fn compute_id_and_check(
        nonce_path: &PathVar<P, F, PG>,
        expected_id: &FpVar<F>,
    ) -> Result<(), SynthesisError> {
        let computed_id = Boolean::<F>::le_bits_to_fp(&nonce_path.get_leaf_position())?;
        Ok(computed_id.enforce_equal(&expected_id)?)
    }
}
