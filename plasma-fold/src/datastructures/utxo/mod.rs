use ark_crypto_primitives::{
    crh::poseidon::{TwoToOneCRH, CRH},
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;

use super::user::UserId;

pub mod constraints;

#[derive(Clone, Debug, Copy, Default, CanonicalSerialize)]
pub struct UTXO {
    pub amount: u64,
    pub id: UserId,
}

pub type UTXOTree<P: Config> = MerkleTree<P>;

pub struct UTXOTreeConfig<F: PrimeField> {
    pub poseidon_conf: PoseidonConfig<F>,
}

impl<F: PrimeField + Absorb> Config for UTXOTreeConfig<F> {
    type Leaf = [F];
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = CRH<F>;
    type TwoToOneHash = TwoToOneCRH<F>;
}
