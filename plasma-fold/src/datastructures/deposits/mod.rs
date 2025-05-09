use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ff::PrimeField;

use crate::primitives::crh::TransactionCRH;

use super::transaction::Transaction;

pub type DepositTree<P: Config> = MerkleTree<P>;

pub struct DepositTreeConfig<F: PrimeField> {
    pub poseidon_conf: PoseidonConfig<F>,
}

impl<F: PrimeField + Absorb> Config for DepositTreeConfig<F> {
    type Leaf = Transaction;
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = TransactionCRH<F>;
    type TwoToOneHash = TwoToOneCRH<F>;
}
