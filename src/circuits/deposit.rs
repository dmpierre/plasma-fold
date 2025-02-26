use ark_crypto_primitives::merkle_tree::{
    constraints::{ConfigGadget, PathVar},
    Config, Path,
};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;

#[derive(Debug, Clone)]
pub struct Deposit<P: Config, F: PrimeField> {
    pub deposit_path: Path<P>,
    pub deposit_root: P::InnerDigest,
    pub deposit_value: [F; 2],
}

#[derive(Debug, Clone)]
pub struct DepositVar<P: Config, F: PrimeField, PG: ConfigGadget<P, F>> {
    pub deposit_path: PathVar<P, F, PG>,
    pub deposit_root: PG::InnerDigest,
    pub deposit_value: [FpVar<F>; 2],
}

impl<P: Config, F: PrimeField> Default for Deposit<P, F> {
    fn default() -> Self {
        let default_deposit_path = Path::default();
        let default_deposit_root = P::InnerDigest::default();
        let default_deposit_value = [F::ZERO, F::ZERO];
        return Deposit {
            deposit_path: default_deposit_path,
            deposit_root: default_deposit_root,
            deposit_value: default_deposit_value,
        };
    }
}
