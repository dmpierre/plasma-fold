use ark_crypto_primitives::{
    crh::poseidon::constraints::TwoToOneCRHGadget,
    merkle_tree::{constraints::ConfigGadget, IdentityDigestConverter},
    sponge::{constraints::AbsorbGadget, Absorb},
};
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};

use crate::{
    datastructures::{utxo::constraints::UTXOVar, TX_IO_SIZE},
    primitives::crh::constraints::TransactionVarCRH,
};

use super::{Transaction, TransactionTreeConfig};

impl<F: PrimeField> AbsorbGadget<F> for TransactionVar<F> {
    fn to_sponge_bytes(
        &self,
    ) -> Result<Vec<ark_r1cs_std::prelude::UInt8<F>>, ark_relations::r1cs::SynthesisError> {
        todo!()
    }

    fn to_sponge_field_elements(
        &self,
    ) -> Result<Vec<FpVar<F>>, ark_relations::r1cs::SynthesisError> {
        todo!()
    }
}

#[derive(Debug)]
pub struct TransactionVar<F: PrimeField> {
    inputs: [UTXOVar<F>; TX_IO_SIZE],
    outputs: [UTXOVar<F>; TX_IO_SIZE],
    nonce: FpVar<F>,
}

impl<F: PrimeField> AllocVar<Transaction, F> for TransactionVar<F> {
    fn new_variable<T: std::borrow::Borrow<Transaction>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        todo!()
    }
}

impl<F: PrimeField + Absorb> ConfigGadget<TransactionTreeConfig<F>, F>
    for TransactionTreeConfig<F>
{
    type Leaf = TransactionVar<F>;
    type LeafDigest = FpVar<F>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<F>>;
    type InnerDigest = FpVar<F>;
    type LeafHash = TransactionVarCRH<F>;
    type TwoToOneHash = TwoToOneCRHGadget<F>;
}
