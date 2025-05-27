use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};

use super::Block;

pub struct BlockVar<F: PrimeField> {
    pub utxo_tree_root: FpVar<F>,
    pub tx_tree_root: FpVar<F>,
    pub signer_tree_root: FpVar<F>,
}

impl<F: PrimeField> AllocVar<Block<F>, F> for BlockVar<F> {
    fn new_variable<T: std::borrow::Borrow<Block<F>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        let cs = cs.into().cs();
        let res = f()?;
        let block = res.borrow();
        let utxo_tree_root = FpVar::new_variable(cs.clone(), || Ok(block.utxo_tree_root), mode)?;
        let tx_tree_root = FpVar::new_variable(cs.clone(), || Ok(block.tx_tree_root), mode)?;
        let signer_tree_root =
            FpVar::new_variable(cs.clone(), || Ok(block.signer_tree_root), mode)?;
        Ok(BlockVar {
            utxo_tree_root,
            tx_tree_root,
            signer_tree_root,
        })
    }
}
