use std::marker::PhantomData;

use crate::datastructures::user::UserId;
use ark_crypto_primitives::{
    crh::poseidon::{TwoToOneCRH, CRH},
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    sponge::Absorb,
};
use ark_ff::PrimeField;

pub type SignerList = Vec<UserId>;

pub type SignerTree<P: Config> = MerkleTree<P>;

pub struct SignerTreeConfig<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> Config for SignerTreeConfig<F> {
    type Leaf = [F];
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = CRH<F>;
    type TwoToOneHash = TwoToOneCRH<F>;
}
