use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::{
        poseidon::{
            constraints::{CRHParametersVar, TwoToOneCRHGadget},
            TwoToOneCRH,
        },
        sha256::{
            constraints::{Sha256Gadget, UnitVar},
            Sha256,
        },
    },
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, groups::CurveVar};
use ark_relations::gr1cs::{ConstraintSystemRef, SynthesisError};
use circuits::{UserAux, UserAuxVar, UserCircuit};
use folding_schemes::{frontend::FCircuit, Error};
use plasma_fold::primitives::accumulator::constraints::{
    PoseidonAccumulatorVar, Sha256AccumulatorVar,
};

pub mod circuits;

#[derive(Debug, Clone)]
pub struct ClientCircuitPoseidon<
    F: PrimeField,
    C: CurveGroup,
    CVar: CurveVar<C, F>,
    const N_TX_PER_FOLD_STEP: usize,
> {
    _f: PhantomData<F>,
    _c: PhantomData<C>,
    _cvar: PhantomData<CVar>,
    params: PoseidonConfig<F>,
}

impl<
        F: PrimeField + Absorb,
        C: CurveGroup<BaseField = F>,
        CVar: CurveVar<C, F>,
        const N_TX_PER_FOLD_STEP: usize,
    > FCircuit<F> for ClientCircuitPoseidon<F, C, CVar, N_TX_PER_FOLD_STEP>
{
    type Params = PoseidonConfig<F>;
    type ExternalInputs = UserAux<F, C, N_TX_PER_FOLD_STEP>;
    type ExternalInputsVar = UserAuxVar<F, C, CVar>;

    fn new(params: Self::Params) -> Result<Self, Error> {
        Ok(Self {
            _f: PhantomData::<F>,
            _c: PhantomData::<C>,
            _cvar: PhantomData::<CVar>,
            params,
        })
    }
    fn state_len(&self) -> usize {
        7
    }
    /// generates the constraints for the step of F for the given z_i
    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let pp = CRHParametersVar::new_constant(cs.clone(), self.params.clone())?;

        let user_circuit = UserCircuit::<
            F,
            C,
            CVar,
            TwoToOneCRH<F>,
            TwoToOneCRHGadget<F>,
            PoseidonAccumulatorVar<F>,
            N_TX_PER_FOLD_STEP,
        >::new(pp.clone(), pp.clone());

        user_circuit.update_balance(cs, z_i, external_inputs)
    }
}

#[derive(Debug, Clone)]
pub struct ClientCircuitSha<
    F: PrimeField,
    C: CurveGroup,
    CVar: CurveVar<C, F>,
    const N_TX_PER_FOLD_STEP: usize,
> {
    _f: PhantomData<F>,
    _c: PhantomData<C>,
    _cvar: PhantomData<CVar>,
    params: PoseidonConfig<F>,
}

impl<
        F: PrimeField + Absorb,
        C: CurveGroup<BaseField = F>,
        CVar: CurveVar<C, F>,
        const N_TX_PER_FOLD_STEP: usize,
    > FCircuit<F> for ClientCircuitSha<F, C, CVar, N_TX_PER_FOLD_STEP>
{
    type Params = PoseidonConfig<F>;
    type ExternalInputs = UserAux<F, C, N_TX_PER_FOLD_STEP>;
    type ExternalInputsVar = UserAuxVar<F, C, CVar>;

    fn new(params: Self::Params) -> Result<Self, Error> {
        Ok(Self {
            _f: PhantomData::<F>,
            _c: PhantomData::<C>,
            _cvar: PhantomData::<CVar>,
            params,
        })
    }
    fn state_len(&self) -> usize {
        7
    }
    /// generates the constraints for the step of F for the given z_i
    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let pp = CRHParametersVar::new_constant(cs.clone(), self.params.clone())?;
        let user_circuit = UserCircuit::<
            F,
            C,
            CVar,
            Sha256,
            Sha256Gadget<F>,
            Sha256AccumulatorVar<F>,
            N_TX_PER_FOLD_STEP,
        >::new(UnitVar::new_constant(cs.clone(), ())?, pp.clone());

        user_circuit.update_balance(cs, z_i, external_inputs)
    }
}
