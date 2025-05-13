use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::poseidon::constraints::TwoToOneCRHGadget,
    merkle_tree::{constraints::ConfigGadget, IdentityDigestConverter},
    sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;

use crate::{datastructures::user::UserIdVar, primitives::crh::constraints::UserIdVarCRH};

use super::SignerTreeConfig;

pub struct SignerTreeConfigGadget<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> ConfigGadget<SignerTreeConfig<F>, F> for SignerTreeConfigGadget<F> {
    type Leaf = UserIdVar<F>;
    type LeafDigest = FpVar<F>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<F>>;
    type InnerDigest = FpVar<F>;
    type LeafHash = UserIdVarCRH<F>;
    type TwoToOneHash = TwoToOneCRHGadget<F>;
}
