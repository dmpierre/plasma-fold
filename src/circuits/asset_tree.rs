/// This module defines the asset tree and the various types of proofs which can be used to update
/// it. An asset tree can be updated in the case of a deposit, a transfer, a receive or a withdraw
/// action. Each has a different type of proof and a corresponding logic for updating the plasma
/// user's asset tree. For instance, `ProofAssetTreeUpdateFromDeposit` defines a proof which is
/// used to update the asset tree following a deposit.
use std::usize;

use ark_crypto_primitives::merkle_tree::{
    constraints::{ConfigGadget, PathVar},
    Config, Path,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::r1cs::ConstraintSystemRef;

pub const ASSET_TREE_N_TOKENS: usize = 10;

#[derive(Debug, Clone)]
pub struct AssetTree<P: Config> {
    pub root: P::InnerDigest, // root of the asset tree
}

// A proof for updating the asset tree, given a valid deposit
// Updates a leaf in the asset tree and the asset tree root
#[derive(Debug, Clone)]
pub struct ProofAssetTreeUpdateFromDeposit<P: Config, F: PrimeField> {
    pub prev_value_path: Path<P>, // path showing membership of old leaf in the asset tree
    pub prev_value: [F; 1],       // previous leaf value in asset tree
    pub prev_root: P::InnerDigest, // prev root of the asset tree, before the deposit
}

impl<P: Config, F: PrimeField> Default for ProofAssetTreeUpdateFromDeposit<P, F> {
    fn default() -> Self {
        Self {
            prev_value_path: Path::default(),
            prev_value: [F::ZERO; 1],
            prev_root: P::InnerDigest::default(),
        }
    }
}

// A proof for updating the asset tree, given a valid deposit
// Updates a leaf in the asset tree and the asset tree root
#[derive(Debug, Clone)]
pub struct ProofAssetTreeUpdateFromDepositVar<P: Config, F: PrimeField, PG: ConfigGadget<P, F>> {
    pub prev_value_path: PathVar<P, F, PG>, // path showing membership of old leaf in the asset tree
    pub prev_value: [FpVar<F>; 1],          // previous leaf value in asset tree
    pub prev_root: PG::InnerDigest,         // prev root of the asset tree, before the deposit
}

impl<P: Config, F: PrimeField, PG: ConfigGadget<P, F>>
    AllocVar<ProofAssetTreeUpdateFromDeposit<P, F>, F>
    for ProofAssetTreeUpdateFromDepositVar<P, F, PG>
{
    fn new_variable<T: std::borrow::Borrow<ProofAssetTreeUpdateFromDeposit<P, F>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        f().and_then(|val| {
            let proof: &ProofAssetTreeUpdateFromDeposit<P, F> = val.borrow();
            let prev_root =
                PG::InnerDigest::new_witness(ark_relations::ns!(cs, "prev_root"), || {
                    Ok(&proof.prev_root)
                })?;
            let prev_value_path = PathVar::<P, F, PG>::new_witness(
                ark_relations::ns!(cs, "prev_value_path"),
                || Ok(&proof.prev_value_path),
            )?;
            let prev_value =
                AllocVar::<[F; 1], F>::new_witness(ark_relations::ns!(cs, "prev_value"), || {
                    Ok(&proof.prev_value)
                })?;
            Ok(ProofAssetTreeUpdateFromDepositVar {
                prev_root,
                prev_value_path,
                prev_value,
            })
        })
    }
}

impl<P: Config> Default for AssetTree<P> {
    fn default() -> Self {
        let default_asset_tree_root = P::InnerDigest::default();
        return AssetTree {
            root: default_asset_tree_root,
        };
    }
}

#[derive(Debug, Clone)]
pub struct AssetTreeVar<P: Config, F: PrimeField, PG: ConfigGadget<P, F>> {
    pub root: PG::InnerDigest, // root of the asset tree
}

impl<P: Config, F: PrimeField, PG: ConfigGadget<P, F>> AssetTreeVar<P, F, PG> {
    fn update_from_deposit(
        cs: ConstraintSystemRef<F>,
        update_proof: &ProofAssetTreeUpdateFromDepositVar<P, F, PG>,
    ) {
        todo!();
    }
    fn update_from_transfer() {
        todo!();
    }
    fn update_from_receive() {
        todo!();
    }
    fn update_from_withdraw() {
        todo!();
    }
}

impl<P: Config, F: PrimeField, PG: ConfigGadget<P, F>> AllocVar<AssetTree<P>, F>
    for AssetTreeVar<P, F, PG>
{
    fn new_variable<T: std::borrow::Borrow<AssetTree<P>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        f().and_then(|val| {
            let asset_tree: &AssetTree<P> = val.borrow();
            let root =
                PG::InnerDigest::new_witness(ark_relations::ns!(cs, "asset_tree_root"), || {
                    Ok(&asset_tree.root)
                })?;
            Ok(AssetTreeVar { root })
        })
    }
}
