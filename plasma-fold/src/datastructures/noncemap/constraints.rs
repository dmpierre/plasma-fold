use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::poseidon::constraints::TwoToOneCRHGadget,
    merkle_tree::{constraints::ConfigGadget, IdentityDigestConverter},
    sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, uint64::UInt64};

use crate::primitives::{crh::constraints::NonceVarCRH, sparsemt::constraints::SparseConfigGadget};

use super::NonceTreeConfig;

pub type NonceVar<F> = UInt64<F>;
pub struct NonceTreeConfigGadget<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> ConfigGadget<NonceTreeConfig<F>, F> for NonceTreeConfigGadget<F> {
    type Leaf = NonceVar<F>;
    type LeafDigest = FpVar<F>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<F>>;
    type InnerDigest = FpVar<F>;
    type LeafHash = NonceVarCRH<F>;
    type TwoToOneHash = TwoToOneCRHGadget<F>;
}

impl<F: PrimeField + Absorb> SparseConfigGadget<NonceTreeConfig<F>, F>
    for NonceTreeConfigGadget<F>
{
    const HEIGHT: u64 = 32;
}
