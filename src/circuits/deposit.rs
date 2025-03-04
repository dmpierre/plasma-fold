/// This module defines deposits, i.e. assets which are deposited in the rollup contract and then
/// included into a deposit tree. For a plasma user to prove a deposit, it will require a merkle
/// proof attesting to the inclusion of a deposit within a deposit tree.
use ark_crypto_primitives::merkle_tree::{
    constraints::{ConfigGadget, PathVar},
    Config, Path,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, prelude::Boolean};

#[derive(Debug, Clone)]
pub struct Deposit<P: Config, F: PrimeField> {
    pub path: Path<P>,        // path from leaf to root of the deposit tree
    pub root: P::InnerDigest, // deposit tree root
    pub value: [F; 1],        // leaf value
    pub flag: bool,           // indicates whether a deposit occured
}

#[derive(Debug, Clone)]
pub struct DepositVar<P: Config, F: PrimeField, PG: ConfigGadget<P, F>> {
    pub path: PathVar<P, F, PG>,
    pub root: PG::InnerDigest, // deposit tree root
    pub value: [FpVar<F>; 1],  // leaf value
    pub flag: Boolean<F>,
}

impl<P: Config, F: PrimeField> Default for Deposit<P, F> {
    fn default() -> Self {
        let default_deposit_path = Path::default();
        let default_deposit_root = P::InnerDigest::default();
        let default_deposit_value = [F::ZERO];
        let default_deposit_flag = bool::default(); // false
        return Deposit {
            path: default_deposit_path,
            root: default_deposit_root,
            value: default_deposit_value,
            flag: default_deposit_flag,
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
            let root =
                PG::InnerDigest::new_witness(ark_relations::ns!(cs, "deposit_root"), || {
                    Ok(&deposit.root)
                })?;
            let value = AllocVar::<[F; 1], F>::new_witness(
                ark_relations::ns!(cs, "deposit_value"),
                || Ok(&deposit.value),
            )?;
            let flag =
                Boolean::new_witness(ark_relations::ns!(cs, "deposit_flag"), || Ok(deposit.flag))?;
            let path =
                PathVar::<P, F, PG>::new_witness(ark_relations::ns!(cs, "deposit_path"), || {
                    Ok(&deposit.path)
                })?;
            Ok(DepositVar {
                path,
                root,
                value,
                flag,
            })
        })
    }
}
