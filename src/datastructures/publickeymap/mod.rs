use std::iter::Map;

use ark_crypto_primitives::{
    crh::poseidon::{TwoToOneCRH, CRH},
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;

use crate::primitives::schnorr::PublicKey;

use super::user::UserId;

pub type PublicKeyMap<C: AffineRepr> = Map<UserId<C::ScalarField>, PublicKey<C>>;

pub type PublicKeyTree<P: Config> = MerkleTree<P>;

pub struct SignerTreeConfig<F: PrimeField> {
    pub poseidon_conf: PoseidonConfig<F>,
}

impl<F: PrimeField + Absorb> Config for SignerTreeConfig<F> {
    type Leaf = [F];
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = CRH<F>;
    type TwoToOneHash = TwoToOneCRH<F>;
}
