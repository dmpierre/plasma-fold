use ark_crypto_primitives::merkle_tree::{constraints::ConfigGadget, Config};
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;

use super::deposit;

/// A block is composed of three things a transaction tree, a deposit tree and a withdrawal tree
/// We store in the struct the root of each of those three trees
#[derive(Debug, Clone)]
pub struct Block<P: Config> {
    transaction_tree_root: P::InnerDigest,
    deposit_tree_root: P::InnerDigest,
    withdrawal_tree_root: P::InnerDigest,
}

impl<P: Config> Default for Block<P> {
    fn default() -> Self {
        Self {
            transaction_tree_root: P::InnerDigest::default(),
            deposit_tree_root: P::InnerDigest::default(),
            withdrawal_tree_root: P::InnerDigest::default(),
        }
    }
}

/// A block is composed of three things: a previous block hash, a transaction tree, a deposit tree and a withdrawal tree
/// We store in the struct the root of each of those three trees
#[derive(Debug, Clone)]
pub struct BlockVar<P: Config, F: PrimeField, PG: ConfigGadget<P, F>> {
    transaction_tree_root: PG::InnerDigest,
    deposit_tree_root: PG::InnerDigest,
    withdrawal_tree_root: PG::InnerDigest,
}

impl<P: Config, F: PrimeField, PG: ConfigGadget<P, F>> AllocVar<Block<P>, F>
    for BlockVar<P, F, PG>
{
    fn new_variable<T: std::borrow::Borrow<Block<P>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        f().and_then(|val| {
            let block: &Block<P> = val.borrow();
            let transaction_tree_root =
                PG::InnerDigest::new_witness(ark_relations::ns!(cs, "tx_root"), || {
                    Ok(&block.transaction_tree_root)
                })?;
            let deposit_tree_root =
                PG::InnerDigest::new_witness(ark_relations::ns!(cs, "deposit_root"), || {
                    Ok(&block.deposit_tree_root)
                })?;
            let withdrawal_tree_root =
                PG::InnerDigest::new_witness(ark_relations::ns!(cs, "withdrawal_root"), || {
                    Ok(&block.withdrawal_tree_root)
                })?;
            Ok(BlockVar {
                transaction_tree_root,
                deposit_tree_root,
                withdrawal_tree_root,
            })
        })
    }
}
