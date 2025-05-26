use ark_crypto_primitives::{
    crh::poseidon::constraints::TwoToOneCRHGadget,
    merkle_tree::{constraints::ConfigGadget, IdentityDigestConverter},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, groups::CurveVar};
use std::marker::PhantomData;

use crate::{
    datastructures::keypair::constraints::PublicKeyVar,
    primitives::crh::constraints::PublicKeyVarCRH,
};

use super::SignerTreeConfig;

pub struct SignerTreeConfigGadget<F: PrimeField, C: CurveGroup, CVar: CurveVar<C, F>> {
    _f: PhantomData<F>,
    _c: PhantomData<C>,
    _cvar: PhantomData<CVar>,
}

impl<F: PrimeField, C: CurveGroup<BaseField = F>, CVar: CurveVar<C, F>>
    ConfigGadget<SignerTreeConfig<C>, C::BaseField> for SignerTreeConfigGadget<F, C, CVar>
where
    C::BaseField: Absorb,
{
    type Leaf = PublicKeyVar<C, CVar>;
    type LeafDigest = FpVar<C::BaseField>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<C::BaseField>>;
    type InnerDigest = FpVar<C::BaseField>;
    type LeafHash = PublicKeyVarCRH<C, CVar>;
    type TwoToOneHash = TwoToOneCRHGadget<C::BaseField>;
}
