use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::poseidon::constraints::TwoToOneCRHGadget,
    merkle_tree::{constraints::ConfigGadget, Config, IdentityDigestConverter},
    sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};

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
