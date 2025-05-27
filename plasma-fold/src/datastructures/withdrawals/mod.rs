use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

use crate::primitives::crh::TransactionCRH;

use super::transaction::Transaction;

pub type WithdrawTree<P: Config> = MerkleTree<P>;

pub struct WithdrawTreeConfig<F: PrimeField, C: CurveGroup> {
    _f: PhantomData<F>,
    _c: PhantomData<C>,
}

impl<F: PrimeField + Absorb, C: CurveGroup<BaseField = F>> Config for WithdrawTreeConfig<F, C> {
    type Leaf = Transaction<C>;
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = TransactionCRH<F, C>;
    type TwoToOneHash = TwoToOneCRH<F>;
}
