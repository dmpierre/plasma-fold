use ark_crypto_primitives::{
    sponge::{poseidon::PoseidonConfig, Absorb},
    Error,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use ark_std::UniformRand;

use super::{
    keypair::{KeyPair, Signature},
    noncemap::Nonce,
    transaction::Transaction,
};

pub mod constraints;

pub const ROLLUP_CONTRACT_ID: u32 = 0;

pub type UserId = u32;

#[derive(Clone)]
pub struct User<C: CurveGroup> {
    pub keypair: KeyPair<C>,
    pub balance: u64,
    pub nonce: Nonce,
    pub acc: C::ScalarField,
    pub id: UserId,
}

impl<
        F: PrimeField + Absorb,
        F2: PrimeField + Absorb,
        C: CurveGroup<ScalarField = F, BaseField = F2>,
    > User<C>
{
    pub fn new(rng: &mut impl Rng, id: UserId) -> Self {
        Self {
            keypair: KeyPair::new(rng),
            nonce: Nonce(0),
            balance: u64::default(),
            acc: C::ScalarField::default(),
            id,
        }
    }
    pub fn sign(
        &self,
        pp: &PoseidonConfig<F2>,
        m: &[F2],
        rng: &mut impl Rng,
    ) -> Result<Signature<F>, Error> {
        self.keypair.sk.sign::<C>(pp, m, rng)
    }

    pub fn spend_transaction(&mut self, tx: Transaction<C>) {
        for utxo in tx.inputs.iter().filter(|utxo| !utxo.is_dummy) {
            self.balance -= utxo.amount;
        }
        self.nonce.0 += 1;
    }

    pub fn receive_transaction(&mut self, tx: Transaction<C>) {
        for utxo in tx.outputs.iter().filter(|utxo| !utxo.is_dummy) {
            self.balance += utxo.amount;
        }
    }
}

pub fn sample_user<C: CurveGroup<BaseField: PrimeField + Absorb>>(rng: &mut impl Rng) -> User<C> {
    let keypair = KeyPair::new(rng);
    let id = UserId::rand(rng);
    User {
        keypair,
        nonce: Nonce(u64::rand(rng)),
        balance: u64::default(),
        acc: C::ScalarField::default(),
        id,
    }
}
