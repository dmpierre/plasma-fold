use ark_crypto_primitives::merkle_tree::constraints::ConfigGadget;
use ark_crypto_primitives::merkle_tree::constraints::PathVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::Boolean;
use ark_relations::r1cs::SynthesisError;
use std::marker::PhantomData;

use ark_crypto_primitives::merkle_tree::Config;
use ark_ff::PrimeField;

pub struct TreeGadgets<P: Config, F: PrimeField, PG: ConfigGadget<P, F>> {
    _f: PhantomData<P>,
    _f1: PhantomData<F>,
    _f2: PhantomData<PG>,
}

impl<P: Config, F: PrimeField, PG: ConfigGadget<P, F>> TreeGadgets<P, F, PG> {
    pub fn compute_id_and_check(
        path: &PathVar<P, F, PG>,
        expected_id: &FpVar<F>,
    ) -> Result<(), SynthesisError> {
        let computed_id = Boolean::<F>::le_bits_to_fp(&path.get_leaf_position())?;
        Ok(computed_id.enforce_equal(&expected_id)?)
    }
}
