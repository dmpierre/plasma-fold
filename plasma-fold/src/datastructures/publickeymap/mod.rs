use crate::primitives::crh::PublicKeyCRH;
use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use std::{iter::Map, marker::PhantomData};

use super::{keypair::PublicKey, user::UserId};

pub mod constraints;

pub type PublicKeyMap<C: CurveGroup> = Map<UserId, PublicKey<C>>;
pub type PublicKeyTree<P: Config> = MerkleTree<P>;

impl<C: CurveGroup<BaseField: PrimeField + Absorb>> Absorb for PublicKey<C> {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        let (x, y) = self.key.into_affine().xy().unwrap();
        dest.extend(x.into_bigint().to_bytes_le());
        dest.extend(y.into_bigint().to_bytes_le());
    }

    fn to_sponge_field_elements<F_: PrimeField>(&self, dest: &mut Vec<F_>) {
        let (x, y) = self.key.into_affine().xy().unwrap();
        x.to_sponge_field_elements(dest);
        y.to_sponge_field_elements(dest);
    }
}

pub struct PublicKeyTreeConfig<C: CurveGroup<BaseField: PrimeField + Absorb>> {
    pub poseidon_conf: PoseidonConfig<C::BaseField>,
    _c: PhantomData<C>,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>> Config for PublicKeyTreeConfig<C> {
    type Leaf = PublicKey<C>;
    type LeafDigest = C::BaseField;
    type LeafInnerDigestConverter = IdentityDigestConverter<C::BaseField>;
    type InnerDigest = C::BaseField;
    type LeafHash = PublicKeyCRH<C>;
    type TwoToOneHash = TwoToOneCRH<C::BaseField>;
}
