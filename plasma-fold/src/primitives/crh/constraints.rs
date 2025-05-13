use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::{
        poseidon::constraints::{CRHGadget, CRHParametersVar},
        CRHSchemeGadget,
    },
    sponge::{constraints::AbsorbGadget, Absorb},
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, groups::CurveVar};

use crate::datastructures::{
    keypair::constraints::PublicKeyVar, noncemap::constraints::NonceVar,
    transaction::constraints::TransactionVar, user::UserIdVar,
};

use super::{NonceCRH, PublicKeyCRH, TransactionCRH, UserIdCRH};

pub struct TransactionVarCRH<F: PrimeField> {
    _f: PhantomData<F>,
}

pub struct NonceVarCRH<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField> TransactionVarCRH<F> {
    pub fn new() -> Self {
        Self { _f: PhantomData }
    }
}

impl<F: PrimeField + Absorb> CRHSchemeGadget<TransactionCRH<F>, F> for TransactionVarCRH<F> {
    type InputVar = TransactionVar<F>;
    type OutputVar = FpVar<F>;
    type ParametersVar = CRHParametersVar<F>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        let elements = input.to_sponge_field_elements()?;
        Ok(CRHGadget::evaluate(parameters, &elements)?)
    }
}

impl<F: PrimeField + Absorb> CRHSchemeGadget<NonceCRH<F>, F> for NonceVarCRH<F> {
    type InputVar = [NonceVar<F>];
    type OutputVar = FpVar<F>;
    type ParametersVar = CRHParametersVar<F>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        Ok(CRHGadget::evaluate(parameters, input)?)
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
        Ok(CRHGadget::evaluate(parameters, &key)?)
    }
}

pub struct UserIdVarCRH<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> CRHSchemeGadget<UserIdCRH<F>, F> for UserIdVarCRH<F> {
    type InputVar = UserIdVar<F>;
    type OutputVar = FpVar<F>;
    type ParametersVar = CRHParametersVar<F>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &Self::InputVar,
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        CRHGadget::evaluate(parameters, &[input.clone()])
    }
}
