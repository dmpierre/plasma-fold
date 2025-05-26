// z_i is (balance, nonce, id, acc)
// z_i is a vec of FpVar<F> in sonobe
// accumulate the block into the block accumulator (acc)
//

use std::marker::PhantomData;

use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;

pub struct UserCircuit<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField> UserCircuit<F> {
    pub fn update_balance(z_i: Vec<FpVar<F>>) {}
}
