mod utils;

use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, Zero};
use ark_std::rand::Rng;
use plasma_fold::datastructures::{keypair::KeyPair, noncemap::Nonce, transaction::Transaction};
use wasm_bindgen::prelude::*;

pub struct UserState<C: CurveGroup> {
    pub key: KeyPair<C>,
    pub balance: u64,
    pub nonce: Nonce,
    pub acc: C::ScalarField,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>> UserState<C> {
    pub fn new(rng: &mut impl Rng) -> Self {
        let key = KeyPair::new(rng);
        Self {
            key,
            balance: 0,
            nonce: Nonce(0),
            acc: C::ScalarField::zero(),
        }
    }

    pub fn spend_transaction(&mut self, tx: Transaction) {
        for utxo in tx.inputs.iter().filter(|utxo| !utxo.is_dummy) {
            self.balance -= utxo.amount;
        }
        self.nonce.0 += 1;
    }

    pub fn receive_transaction(&mut self, tx: Transaction) {
        for utxo in tx.outputs.iter().filter(|utxo| !utxo.is_dummy) {
            self.balance += utxo.amount;
        }
    }

    pub fn to_ivc_inputs(&self) {
        todo!()
    }
}

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

#[wasm_bindgen]
pub fn greet() {
    alert("Hello, client!");
}
