use ark_crypto_primitives::merkle_tree::{
    constraints::{ConfigGadget, PathVar},
    Config, Path,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, prelude::Boolean};

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

impl<P: Config, F: PrimeField, PG: ConfigGadget<P, F>> AllocVar<Deposit<P, F>, F>
    for DepositVar<P, F, PG>
{
    fn new_variable<T: std::borrow::Borrow<Deposit<P, F>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        f().and_then(|val| {
            let deposit: &Deposit<P, F> = val.borrow();
            let deposit_root =
                PG::InnerDigest::new_witness(ark_relations::ns!(cs, "deposit_root"), || {
                    Ok(&deposit.deposit_root)
                })?;
            let deposit_path =
                PathVar::<P, F, PG>::new_witness(ark_relations::ns!(cs, "deposit_path"), || {
                    Ok(&deposit.deposit_path)
                })?;
            let deposit_value = AllocVar::<[F; 2], F>::new_witness(
                ark_relations::ns!(cs, "deposit_value"),
                || Ok(&deposit.deposit_value),
            )?;
            let deposit_flag =
                Boolean::new_witness(ark_relations::ns!(cs, "deposit_flag"), || {
                    Ok(deposit.deposit_flag)
                })?;
            Ok(DepositVar {
                deposit_path,
                deposit_root,
                deposit_value,
                deposit_flag,
            })
        })
    }
}
