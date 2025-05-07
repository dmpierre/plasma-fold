use std::{iter::Map, marker::PhantomData};

use ark_crypto_primitives::{
    crh::poseidon::{TwoToOneCRH, CRH},
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;

use crate::primitives::crh::PublicKeyCRH;

use super::user::UserId;

pub struct PublicKey<C: CurveGroup> {
    pub sk: C::ScalarField,
    pub pk: C,
}

pub type PublicKeyMap<C: CurveGroup> = Map<UserId<C::ScalarField>, PublicKey<C>>;
pub type PublicKeyTree<P: Config> = MerkleTree<P>;

impl<F: PrimeField + Absorb, C: CurveGroup<ScalarField = F>> Absorb for PublicKey<C> {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {}

    fn to_sponge_field_elements<F_: PrimeField>(&self, dest: &mut Vec<F_>) {}
}

pub struct PublicKeyTreeConfig<F: PrimeField, C: CurveGroup<ScalarField = F>> {
    pub poseidon_conf: PoseidonConfig<F>,
    _f: PhantomData<C>,
}

impl<F: PrimeField + Absorb, C: CurveGroup<ScalarField = F>> Config for PublicKeyTreeConfig<F, C> {
    type Leaf = PublicKey<C>;
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = PublicKeyCRH<F, C>;
    type TwoToOneHash = TwoToOneCRH<F>;
}
