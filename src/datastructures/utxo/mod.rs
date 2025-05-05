use ark_ff::PrimeField;

// [amount, id]
pub type UTXO<F: PrimeField> = [F; 2];
