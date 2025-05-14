use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    sponge::Absorb,
};
use ark_ff::PrimeField;

use crate::primitives::crh::UTXOCRH;

use super::user::UserId;

pub mod constraints;

#[derive(Clone, Debug, Copy, Default)]
pub struct UTXO {
    pub amount: u64,
    pub id: UserId,
}

pub type UTXOTree<P: Config> = MerkleTree<P>;

pub struct UTXOTreeConfig<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> Config for UTXOTreeConfig<F> {
    type Leaf = UTXO;
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = UTXOCRH<F>;
    type TwoToOneHash = TwoToOneCRH<F>;
}
