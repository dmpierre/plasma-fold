use super::user::UserId;
use ark_crypto_primitives::{
    crh::poseidon::{TwoToOneCRH, CRH},
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ff::PrimeField;
use std::iter::Map;

pub type Nonce<F: PrimeField> = F;
pub type NonceMap<F: PrimeField> = Map<UserId<F>, F>;
pub type NonceTree<P: Config> = MerkleTree<P>;

pub struct NonceTreeConfig<F: PrimeField> {
    pub poseidon_conf: PoseidonConfig<F>,
}

impl<F: PrimeField + Absorb> Config for NonceTreeConfig<F> {
    type Leaf = [Nonce<F>];
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = CRH<F>;
    type TwoToOneHash = TwoToOneCRH<F>;
}
