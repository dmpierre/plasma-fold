use std::marker::PhantomData;

use crate::{
    datastructures::user::UserId,
    primitives::crh::{PublicKeyCRH, UserIdCRH},
};
use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

use super::keypair::PublicKey;

pub mod constraints;

pub type SignerList = Vec<u32>;
pub type SignerTree<P: Config> = MerkleTree<P>;

pub struct SignerTreeConfig<C: CurveGroup> {
    _c: PhantomData<C>,
}

impl<C: CurveGroup<BaseField: Absorb + PrimeField>> Config for SignerTreeConfig<C> {
    type Leaf = PublicKey<C>;
    type LeafDigest = C::BaseField;
    type LeafInnerDigestConverter = IdentityDigestConverter<C::BaseField>;
    type InnerDigest = C::BaseField;
    type LeafHash = PublicKeyCRH<C>;
    type TwoToOneHash = TwoToOneCRH<C::BaseField>;
}
