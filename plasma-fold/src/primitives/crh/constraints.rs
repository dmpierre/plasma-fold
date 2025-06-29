use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::{
        poseidon::constraints::{CRHGadget, CRHParametersVar},
        CRHSchemeGadget,
    },
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, groups::CurveVar};

use crate::datastructures::{
    block::constraints::BlockVar, keypair::constraints::PublicKeyVar,
    noncemap::constraints::NonceVar, transaction::constraints::TransactionVar,
    utxo::constraints::UTXOVar,
};

use super::{BlockCRH, NonceCRH, PublicKeyCRH, TransactionCRH, UTXOCRH};

pub struct TransactionVarCRH<F: PrimeField, C: CurveGroup, CVar: CurveVar<C, F>> {
    _f: PhantomData<F>,
    _c: PhantomData<C>,
    _cvar: PhantomData<CVar>,
}

pub struct NonceVarCRH<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField, C: CurveGroup, CVar: CurveVar<C, F>> Default for TransactionVarCRH<F, C, CVar> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: PrimeField, C: CurveGroup, CVar: CurveVar<C, F>> TransactionVarCRH<F, C, CVar> {
    pub fn new() -> Self {
        Self {
            _f: PhantomData,
            _c: PhantomData,
            _cvar: PhantomData,
        }
    }
}

impl<F: PrimeField + Absorb, C: CurveGroup<BaseField = F>, CVar: CurveVar<C, F>>
    CRHSchemeGadget<TransactionCRH<F, C>, F> for TransactionVarCRH<F, C, CVar>
{
    type InputVar = TransactionVar<F, C, CVar>;
    type OutputVar = FpVar<F>;
    type ParametersVar = CRHParametersVar<F>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        let elements: Vec<FpVar<F>> = input.try_into()?;
        CRHGadget::evaluate(parameters, &elements)
    }
}

impl<F: PrimeField + Absorb> CRHSchemeGadget<NonceCRH<F>, F> for NonceVarCRH<F> {
    type InputVar = NonceVar<F>;
    type OutputVar = FpVar<F>;
    type ParametersVar = CRHParametersVar<F>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        CRHGadget::evaluate(parameters, [input.to_fp()?].as_slice())
    }
}

pub struct PublicKeyVarCRH<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    CVar: CurveVar<C, C::BaseField>,
> {
    _c: PhantomData<C>,
    _c1: PhantomData<CVar>,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>
    CRHSchemeGadget<PublicKeyCRH<C>, C::BaseField> for PublicKeyVarCRH<C, CVar>
{
    type InputVar = PublicKeyVar<C, CVar>;
    type OutputVar = FpVar<C::BaseField>;
    type ParametersVar = CRHParametersVar<C::BaseField>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        let key = input.key.to_constraint_field()?;
        CRHGadget::evaluate(parameters, &key)
    }
}

pub struct UTXOVarCRH<F: PrimeField, C: CurveGroup<BaseField = F>, CVar: CurveVar<C, F>> {
    _f: PhantomData<F>,
    _c: PhantomData<C>,
    _cv: PhantomData<CVar>,
}

impl<F: PrimeField + Absorb, C: CurveGroup<BaseField = F>, CVar: CurveVar<C, F>>
    CRHSchemeGadget<UTXOCRH<C>, F> for UTXOVarCRH<F, C, CVar>
{
    type InputVar = UTXOVar<F, C, CVar>;
    type OutputVar = FpVar<F>;
    type ParametersVar = CRHParametersVar<F>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        let bool_as_fp: FpVar<F> = input.is_dummy.clone().into();
        let pk_point = input.pk.key.to_constraint_field()?;
        let mut input = Vec::from([input.amount.clone(), bool_as_fp]);
        for p in pk_point {
            input.push(p);
        }
        CRHGadget::evaluate(parameters, &input)
    }
}

pub struct BlockVarCRH<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> CRHSchemeGadget<BlockCRH<F>, F> for BlockVarCRH<F> {
    type InputVar = BlockVar<F>;
    type OutputVar = FpVar<F>;
    type ParametersVar = CRHParametersVar<F>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        CRHGadget::evaluate(
            parameters,
            &[
                input.utxo_tree_root.clone(),
                input.tx_tree_root.clone(),
                input.signer_tree_root.clone(),
                input.height.clone(),
            ],
        )
    }
}
