use crate::primitives::schnorr::Schnorr;
use ark_crypto_primitives::{
    sponge::{poseidon::PoseidonConfig, Absorb},
    Error,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_std::rand::Rng;

pub mod constraints;

// Schnorr secret key
#[derive(Clone, Debug)]
pub struct SecretKey<F: PrimeField> {
    pub key: F,
}

impl<F: PrimeField> SecretKey<F> {
    pub fn new(rng: &mut impl Rng) -> Self {
        Self { key: F::rand(rng) }
    }

    pub fn sign<C: CurveGroup<ScalarField = F, BaseField: PrimeField + Absorb>>(
        &self,
        pp: &PoseidonConfig<C::BaseField>,
        m: &[C::BaseField],
        rng: &mut impl Rng,
    ) -> Result<Signature<C::ScalarField>, Error> {
        let (s, e) = Schnorr::sign::<C>(pp, self.key, m, rng)?;
        Ok(Signature { s, e })
    }
}

// Schnorr public key
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Hash)]
pub struct PublicKey<C: CurveGroup> {
    pub key: C,
}

impl<C: CurveGroup> AsRef<PublicKey<C>> for PublicKey<C> {
    fn as_ref(&self) -> &PublicKey<C> {
        self
    }
}

impl<C: CurveGroup> PublicKey<C> {
    pub fn new(sk: &SecretKey<C::ScalarField>) -> Self {
        Self {
            key: C::generator().mul(sk.key),
        }
    }
}

// Schnorr Signature, which is tuple (s, e)
#[derive(Debug, Clone, Default)]
pub struct Signature<F: PrimeField> {
    pub s: F,
    pub e: F,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>> PublicKey<C> {
    pub fn verify_signature(
        &self,
        pp: &PoseidonConfig<C::BaseField>,
        message: &[C::BaseField],
        Signature { s, e }: &Signature<C::ScalarField>,
    ) -> Result<bool, Error> {
        Schnorr::verify::<C>(pp, &self.key, message, (*s, *e))
    }
}

#[derive(Clone, Debug)]
pub struct KeyPair<C: CurveGroup> {
    pub sk: SecretKey<C::ScalarField>,
    pub pk: PublicKey<C>,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>> KeyPair<C> {
    pub fn new(rng: &mut impl Rng) -> Self {
        let (sk, pk) = Schnorr::key_gen::<C>(rng);
        Self {
            sk: SecretKey { key: sk },
            pk: PublicKey { key: pk },
        }
    }
}
