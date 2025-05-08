use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;

pub type UTXOVar<F: PrimeField> = [FpVar<F>; 2];
