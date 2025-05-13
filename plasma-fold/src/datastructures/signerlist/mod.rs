use std::marker::PhantomData;

use crate::{datastructures::user::UserId, primitives::crh::UserIdCRH};
use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    sponge::Absorb,
};
use ark_ff::PrimeField;

pub mod constraints;

pub type SignerList = Vec<UserId>;
pub type SignerTree<P: Config> = MerkleTree<P>;

pub struct SignerTreeConfig<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> Config for SignerTreeConfig<F> {
    type Leaf = UserId;
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = UserIdCRH<F>;
    type TwoToOneHash = TwoToOneCRH<F>;
}
