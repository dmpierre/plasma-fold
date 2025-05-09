use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;

#[derive(Debug)]
pub struct UTXOVar<F: PrimeField> {
    pub amount: FpVar<F>,
    pub id: FpVar<F>,
}
