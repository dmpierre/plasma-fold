use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    sponge::Absorb,
};
use ark_ff::PrimeField;

use crate::primitives::{crh::UTXOCRH, sparsemt::{MerkleSparseTree, SparseConfig}};

use super::user::UserId;

pub mod constraints;

#[derive(Clone, Debug, Copy, PartialEq, Eq, Hash)]
pub struct UTXO {
    pub amount: u64,
    pub id: UserId,
    pub is_dummy: bool,
}

impl UTXO {
    pub fn new(id: UserId, amount: u64) -> Self {
        UTXO {
            amount,
            id,
            is_dummy: false,
        }
    }

    pub fn dummy() -> Self {
        UTXO {
            amount: 0,
            id: 0,
            is_dummy: true,
        }
    }
}

impl Default for UTXO {
    fn default() -> Self {
        UTXO::dummy()
    }
}

pub type UTXOTree<P> = MerkleSparseTree<P>;

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

impl<F: PrimeField + Absorb> SparseConfig for UTXOTreeConfig<F> {
    const HEIGHT: u64 = 32;
}