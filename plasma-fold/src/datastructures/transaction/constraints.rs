use std::{convert::TryInto, marker::PhantomData};

use ark_crypto_primitives::{
    crh::poseidon::constraints::TwoToOneCRHGadget,
    merkle_tree::{constraints::ConfigGadget, IdentityDigestConverter},
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    groups::CurveVar,
    prelude::Boolean,
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::borrow::Borrow;

use crate::{
    datastructures::{
        keypair::constraints::PublicKeyVar, noncemap::constraints::NonceVar,
        utxo::constraints::UTXOVar, TX_IO_SIZE,
    },
    primitives::{crh::constraints::TransactionVarCRH, sparsemt::constraints::SparseConfigGadget},
    TX_TREE_HEIGHT,
};

use super::{Transaction, TransactionTreeConfig};

impl<F: PrimeField + Absorb, C: CurveGroup<BaseField = F>, CVar: CurveVar<C, F>>
    TryInto<Vec<FpVar<F>>> for &TransactionVar<F, C, CVar>
{
    type Error = SynthesisError;
    fn try_into(self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let mut arr = Vec::new();
        for utxo in self.inputs.iter().chain(&self.outputs) {
            arr.push(utxo.amount.clone());
            arr.push(utxo.is_dummy.clone().into());
            let point = utxo.pk.key.to_constraint_field()?;
            for p in point {
                arr.push(p);
            }
        }
        arr.push(self.nonce.clone());
        Ok(arr)
    }
}

#[derive(Debug)]
pub struct TransactionVar<
    F: PrimeField + Absorb,
    C: CurveGroup<BaseField = F>,
    CVar: CurveVar<C, F>,
> {
    pub inputs: [UTXOVar<F, C, CVar>; TX_IO_SIZE],
    pub outputs: [UTXOVar<F, C, CVar>; TX_IO_SIZE],
    pub nonce: FpVar<F>,
}

impl<F: PrimeField + Absorb, C: CurveGroup<BaseField = F>, CVar: CurveVar<C, F>>
    AllocVar<Transaction<C>, F> for TransactionVar<F, C, CVar>
{
    fn new_variable<T: Borrow<Transaction<C>>>(
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
            nonce: FpVar::new_variable(cs, || Ok(F::from(nonce.0)), mode)?,
        })
    }
}

pub struct TransactionTreeConfigGadget<F: PrimeField, C: CurveGroup, CVar: CurveVar<C, F>> {
    _f: PhantomData<F>,
    _c: PhantomData<C>,
    _cvar: PhantomData<CVar>,
}

impl<F: PrimeField + Absorb, C: CurveGroup<BaseField = F>, CVar: CurveVar<C, F>>
    ConfigGadget<TransactionTreeConfig<C>, F> for TransactionTreeConfigGadget<F, C, CVar>
{
    type Leaf = TransactionVar<F, C, CVar>;
    type LeafDigest = FpVar<F>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<F>>;
    type InnerDigest = FpVar<F>;
    type LeafHash = TransactionVarCRH<F, C, CVar>;
    type TwoToOneHash = TwoToOneCRHGadget<F>;
}

impl<F: PrimeField + Absorb, C: CurveGroup<BaseField = F>, CVar: CurveVar<C, F>>
    SparseConfigGadget<TransactionTreeConfig<C>, F> for TransactionTreeConfigGadget<F, C, CVar>
{
    const HEIGHT: u64 = TX_TREE_HEIGHT;
}

impl<F: PrimeField + Absorb, C: CurveGroup<BaseField = F>, CVar: CurveVar<C, F>>
    TransactionVar<F, C, CVar>
{
    pub fn is_valid(
        &self,
        sender: Option<PublicKeyVar<C, CVar>>,
        nonce: Option<NonceVar<F>>,
    ) -> Result<Boolean<F>, SynthesisError> {
        let mut result = Boolean::TRUE;
        let sender = sender.unwrap_or(self.inputs[0].pk.clone());
        for i in &self.inputs {
            result &= i.pk.key.is_eq(&sender.key)?;
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

    pub fn get_signer(&self) -> PublicKeyVar<C, CVar> {
        self.inputs[0].pk.clone()
    }
}
