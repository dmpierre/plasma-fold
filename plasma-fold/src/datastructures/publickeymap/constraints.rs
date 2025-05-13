use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::poseidon::constraints::TwoToOneCRHGadget,
    merkle_tree::{constraints::ConfigGadget, Config, IdentityDigestConverter},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, groups::CurveVar};

use crate::{
    datastructures::keypair::constraints::PublicKeyVar,
    primitives::crh::constraints::PublicKeyVarCRH,
};

use super::PublicKeyTreeConfig;

pub struct PublicKeyTreeConfigGadget<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    CVar: CurveVar<C, C::BaseField>,
    P: Config,
> {
    _p: PhantomData<P>,
    _c: PhantomData<C>,
    _c1: PhantomData<CVar>,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>, P: Config>
    ConfigGadget<PublicKeyTreeConfig<C>, C::BaseField> for PublicKeyTreeConfigGadget<C, CVar, P>
{
    type Leaf = PublicKeyVar<C, CVar>;
    type LeafDigest = FpVar<C::BaseField>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<C::BaseField>>;
    type InnerDigest = FpVar<C::BaseField>;
    type LeafHash = PublicKeyVarCRH<C, CVar>;
    type TwoToOneHash = TwoToOneCRHGadget<C::BaseField>;
}
