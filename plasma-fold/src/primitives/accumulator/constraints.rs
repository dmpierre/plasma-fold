use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::{
        poseidon::constraints::{CRHParametersVar, TwoToOneCRHGadget},
        sha256::{
            constraints::{Sha256Gadget, UnitVar},
            Sha256,
        },
        TwoToOneCRHSchemeGadget,
    },
    sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{convert::ToConstraintFieldGadget, fields::fp::FpVar, prelude::ToBytesGadget};
use ark_relations::r1cs::SynthesisError;

pub struct Sha256AccumulatorVar<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField> Sha256AccumulatorVar<F> {
    pub fn update(prev: FpVar<F>, value: FpVar<F>) -> Result<FpVar<F>, SynthesisError> {
        let right_input = value.to_bytes_le()?;
        let digest = <Sha256Gadget<F> as TwoToOneCRHSchemeGadget<Sha256, F>>::evaluate(
            &UnitVar::default(),
            &prev.to_bytes_le()?,
            &right_input,
        )?
        .0;
        // drop the last byte
        let (_, value) = digest.split_last().unwrap();
        Ok(value.to_constraint_field()?[0].clone())
    }
}

pub struct PoseidonAccumulatorVar<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> PoseidonAccumulatorVar<F> {
    pub fn update(
        pp: &CRHParametersVar<F>,
        prev: &FpVar<F>,
        value: &FpVar<F>,
    ) -> Result<FpVar<F>, SynthesisError> {
        TwoToOneCRHGadget::evaluate(pp, prev, value)
    }
}
