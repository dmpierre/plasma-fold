use ark_crypto_primitives::{
    sponge::{poseidon::PoseidonConfig, Absorb},
    Error,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_std::rand::Rng;

use super::{
    keypair::{KeyPair, Signature},
    noncemap::Nonce,
};

pub type UserId = u32;
pub type UserIdVar<F> = FpVar<F>;

pub struct User<C: CurveGroup> {
    pub id: UserId,
    pub keypair: KeyPair<C>,
    pub nonce: Nonce,
}

impl<
        F: PrimeField + Absorb,
        F2: PrimeField + Absorb,
        C: CurveGroup<ScalarField = F, BaseField = F2>,
    > User<C>
{
    pub fn new(rng: &mut impl Rng, id: UserId) -> Self {
        Self {
            id,
            keypair: KeyPair::new(rng),
            nonce: Nonce(0),
        }
    }
    pub fn sign(
        &self,
        pp: &PoseidonConfig<F2>,
        m: F2,
        rng: &mut impl Rng,
    ) -> Result<Signature<F>, Error> {
        Ok(self.keypair.sk.sign::<C>(pp, m, rng)?)
    }
}
