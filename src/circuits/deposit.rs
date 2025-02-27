use ark_crypto_primitives::merkle_tree::{
    constraints::{ConfigGadget, PathVar},
    Config, Path,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::Boolean};

#[derive(Debug, Clone)]
pub struct Deposit<P: Config, F: PrimeField> {
    pub deposit_path: Path<P>, // path from leaf to root of the deposit tree
    pub deposit_root: P::InnerDigest, // root of the deposit tree
    pub deposit_value: [F; 2], // value of the deposit that has been made
    pub deposit_flag: bool,    // indicates whether a deposit occured
}

#[derive(Debug, Clone)]
pub struct DepositVar<P: Config, F: PrimeField, PG: ConfigGadget<P, F>> {
    pub deposit_path: PathVar<P, F, PG>,
    pub deposit_root: PG::InnerDigest,
    pub deposit_value: [FpVar<F>; 2],
    pub deposit_flag: Boolean<F>,
}

impl<P: Config, F: PrimeField> Default for Deposit<P, F> {
    fn default() -> Self {
        let default_deposit_path = Path::default();
        let default_deposit_root = P::InnerDigest::default();
        let default_deposit_value = [F::ZERO, F::ZERO];
        let default_deposit_flag = bool::default(); // false
        return Deposit {
            deposit_path: default_deposit_path,
            deposit_root: default_deposit_root,
            deposit_value: default_deposit_value,
            deposit_flag: default_deposit_flag,
        };
    }
}
