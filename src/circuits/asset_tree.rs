use std::usize;

use ark_crypto_primitives::merkle_tree::{constraints::ConfigGadget, Config};
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};

pub const ASSET_TREE_N_TOKENS: usize = 10;

#[derive(Debug, Clone)]
pub struct AssetTree<P: Config, F: PrimeField> {
    pub root: P::InnerDigest,                  // root of the asset tree
    pub leaves: [[F; 2]; ASSET_TREE_N_TOKENS], // [..., (token_index, value), ...]
}

impl<P: Config, F: PrimeField> Default for AssetTree<P, F> {
    fn default() -> Self {
        let default_asset_tree_root = P::InnerDigest::default();
        let default_assets_leaves = [[F::ZERO, F::ZERO]; ASSET_TREE_N_TOKENS];
        return AssetTree {
            root: default_asset_tree_root,
            leaves: default_assets_leaves,
        };
    }
}
#[derive(Debug, Clone)]
pub struct AssetTreeVar<P: Config, F: PrimeField, PG: ConfigGadget<P, F>> {
    pub root: PG::InnerDigest,                        // root of the asset tree
    pub leaves: [[FpVar<F>; 2]; ASSET_TREE_N_TOKENS], // [..., (token_index, value), ...]
}

impl<P: Config, F: PrimeField, PG: ConfigGadget<P, F>> AllocVar<AssetTree<P, F>, F>
    for AssetTreeVar<P, F, PG>
{
    fn new_variable<T: std::borrow::Borrow<AssetTree<P, F>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        f().and_then(|val| {
            let asset_tree: &AssetTree<P, F> = val.borrow();
            let root =
                PG::InnerDigest::new_witness(ark_relations::ns!(cs, "deposit_root"), || {
                    Ok(&asset_tree.root)
                })?;
            let leaves = AllocVar::<[[F; 2]; ASSET_TREE_N_TOKENS], F>::new_witness(
                ark_relations::ns!(cs, "deposit_value"),
                || Ok(&asset_tree.leaves),
            )?;
            Ok(AssetTreeVar { root, leaves })
        })
    }
}
