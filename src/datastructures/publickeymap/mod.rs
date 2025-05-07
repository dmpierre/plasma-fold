use crate::primitives::{crh::PublicKeyCRH, schnorr::Schnorr};
use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;
use std::{iter::Map, marker::PhantomData};

use super::user::UserId;

#[derive(Debug, CanonicalSerialize)]
pub struct PublicKey<C: CurveGroup> {
    pub key: C,
}

#[derive(Debug)]
pub struct KeyPair<C: CurveGroup> {
    pub sk: C::ScalarField,
    pub pk: PublicKey<C>,
}

impl<C: CurveGroup> KeyPair<C> {
    pub fn new(rng: &mut impl Rng) -> Self {
        let (sk, pubk) = Schnorr::key_gen::<C>(rng);
        let pk = PublicKey { key: pubk };
        Self { sk, pk }
    }

    pub fn sign() {}

    pub fn verify() {}
}

pub type PublicKeyMap<C: CurveGroup> = Map<UserId<C::ScalarField>, PublicKey<C>>;
pub type PublicKeyTree<P: Config> = MerkleTree<P>;

impl<F: PrimeField + Absorb, C: CurveGroup<ScalarField = F>> Absorb for PublicKey<C>
where
    C::BaseField: Absorb,
{
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        self.serialize_uncompressed(dest).unwrap();
    }

    fn to_sponge_field_elements<F_: PrimeField>(&self, dest: &mut Vec<F_>) {
        let (x, y) = self.key.into_affine().xy().unwrap();
        x.to_sponge_field_elements(dest);
        y.to_sponge_field_elements(dest);
    }
}

pub struct PublicKeyTreeConfig<F: PrimeField, C: CurveGroup<ScalarField = F>> {
    pub poseidon_conf: PoseidonConfig<F>,
    _f: PhantomData<C>,
}

impl<F: PrimeField + Absorb, C: CurveGroup<ScalarField = F>> Config for PublicKeyTreeConfig<F, C>
where
    C::BaseField: Absorb,
{
    type Leaf = PublicKey<C>;
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = PublicKeyCRH<F, C>;
    type TwoToOneHash = TwoToOneCRH<F>;
}
