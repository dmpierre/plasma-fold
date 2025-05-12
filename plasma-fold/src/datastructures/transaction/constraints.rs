use std::{convert::TryInto, marker::PhantomData};

use ark_crypto_primitives::{
    crh::poseidon::constraints::TwoToOneCRHGadget,
    merkle_tree::{constraints::ConfigGadget, Config, IdentityDigestConverter},
    sponge::{constraints::AbsorbGadget, Absorb},
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    prelude::{Boolean, ToBytesGadget},
    uint8::UInt8,
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::borrow::Borrow;

use crate::{
    datastructures::{noncemap::NonceVar, user::UserIdVar, utxo::constraints::UTXOVar, TX_IO_SIZE},
    primitives::crh::constraints::TransactionVarCRH,
};

use super::{Transaction, TransactionTreeConfig};

impl<F: PrimeField> AbsorbGadget<F> for TransactionVar<F> {
    fn to_sponge_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        let mut arr = self
            .inputs
            .iter()
            .chain(&self.outputs)
            .map(|utxo| Ok([utxo.amount.to_bytes_le()?, utxo.id.to_bytes_le()?].concat()))
            .collect::<Result<Vec<_>, _>>()?
            .concat();
        arr.extend(self.nonce.to_bytes_le()?);
        Ok(arr)
    }

    fn to_sponge_field_elements(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let mut arr = self
            .inputs
            .iter()
            .chain(&self.outputs)
            .flat_map(|utxo| [utxo.amount.clone(), utxo.id.clone()])
            .collect::<Vec<_>>();
        arr.push(self.nonce.clone());
        Ok(arr)
    }
}

#[derive(Debug)]
pub struct TransactionVar<F: PrimeField> {
    inputs: [UTXOVar<F>; TX_IO_SIZE],
    outputs: [UTXOVar<F>; TX_IO_SIZE],
    nonce: FpVar<F>,
}

impl<F: PrimeField> AllocVar<Transaction, F> for TransactionVar<F> {
    fn new_variable<T: Borrow<Transaction>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let f = f()?;
        let Transaction {
            inputs,
            outputs,
            nonce,
        } = f.borrow();
        Ok(Self {
            inputs: Vec::new_variable(cs.clone(), || Ok(&inputs[..]), mode)?
                .try_into()
                .unwrap(),
            outputs: Vec::new_variable(cs.clone(), || Ok(&outputs[..]), mode)?
                .try_into()
                .unwrap(),
            nonce: FpVar::new_variable(cs, || Ok(F::from(*nonce)), mode)?,
        })
    }
}

pub struct TransactionTreeConfigGadget<P: Config, F: PrimeField> {
    _f: PhantomData<P>,
    _f1: PhantomData<F>,
}

impl<P: Config, F: PrimeField + Absorb> ConfigGadget<TransactionTreeConfig<F>, F>
    for TransactionTreeConfigGadget<P, F>
{
    type Leaf = TransactionVar<F>;
    type LeafDigest = FpVar<F>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<F>>;
    type InnerDigest = FpVar<F>;
    type LeafHash = TransactionVarCRH<F>;
    type TwoToOneHash = TwoToOneCRHGadget<F>;
}

impl<F: PrimeField> TransactionVar<F> {
    pub fn is_valid(
        &self,
        sender: Option<UserIdVar<F>>,
        nonce: Option<NonceVar<F>>,
    ) -> Result<Boolean<F>, SynthesisError> {
        let mut result = Boolean::TRUE;
        let sender = sender.unwrap_or(self.inputs[0].id.clone());
        for i in &self.inputs {
            result &= i.id.is_eq(&sender)?;
        }
        result &= self
            .inputs
            .iter()
            .zip(&self.outputs)
            .map(|(i, o)| &i.amount - &o.amount)
            .sum::<FpVar<F>>()
            .is_zero()?;
        if let Some(nonce) = nonce {
            result &= self.nonce.is_eq(&nonce)?;
        }
        Ok(result)
    }
}
