use std::marker::PhantomData;

use ark_crypto_primitives::crh::{
    sha256::{
        constraints::{Sha256Gadget, UnitVar},
        digest::KeyInit,
    },
    TwoToOneCRHSchemeGadget,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    convert::ToConstraintFieldGadget, fields::fp::FpVar, prelude::ToBytesGadget, uint8::UInt8,
};
use ark_relations::r1cs::SynthesisError;

pub struct Sha256AccumulatorVar<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField> Sha256AccumulatorVar<F> {
    pub fn update(prev: FpVar<F>, value: FpVar<F>) -> Result<FpVar<F>, SynthesisError> {
        let right_input = value.to_bytes_le()?;
        let digest =
            Sha256Gadget::evaluate(&UnitVar::default(), &prev.to_bytes_le()?, &right_input)?.0;
        // drop the last byte
        let (_, value) = digest.split_last().unwrap();
        Ok(value.to_constraint_field()?[0].clone())
    }
}
