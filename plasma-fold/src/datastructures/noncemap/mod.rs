use crate::primitives::crh::NonceCRH;

use super::user::UserId;
use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use std::iter::Map;

pub type Nonce = u64;
pub type NonceVar<F> = FpVar<F>;
pub type NonceMap = Map<UserId, Nonce>;
pub type NonceTree<P: Config> = MerkleTree<P>;

pub struct NonceTreeConfig<F: PrimeField> {
    pub poseidon_conf: PoseidonConfig<F>,
}

impl<F: PrimeField + Absorb> Config for NonceTreeConfig<F> {
    type Leaf = [Nonce];
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = NonceCRH<F>;
    type TwoToOneHash = TwoToOneCRH<F>;
}
