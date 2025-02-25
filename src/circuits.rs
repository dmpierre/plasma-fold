use std::{borrow::Borrow, marker::PhantomData};

use ark_crypto_primitives::{
    crh::{CRHScheme, CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget},
    merkle_tree::{
        constraints::{ConfigGadget, PathVar},
        Config, Path,
    },
    sponge::Absorb,
};

use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, prelude::Boolean};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use folding_schemes::frontend::FCircuit;

#[derive(Debug, Clone)]
pub struct Deposit<P: Config, F: PrimeField> {
    pub deposit_path: Path<P>,
    pub deposit_root: P::InnerDigest,
    pub deposit_value: [F; 2],
}

#[derive(Debug, Clone)]
pub struct DepositVar<P: Config, F: PrimeField, PG: ConfigGadget<P, F>> {
    pub deposit_path: PathVar<P, F, PG>,
    pub deposit_root: PG::InnerDigest,
    pub deposit_value: [FpVar<F>; 2],
}

impl<P: Config, F: PrimeField> Default for Deposit<P, F> {
    fn default() -> Self {
        let default_deposit_path = Path::default();
        let default_deposit_root = P::InnerDigest::default();
        let default_deposit_value = [F::ZERO, F::ZERO];
        return Deposit {
            deposit_path: default_deposit_path,
            deposit_root: default_deposit_root,
            deposit_value: default_deposit_value,
        };
    }
}

#[derive(Debug, Clone)]
pub struct PlasmaFoldExternalInputs<P: Config, F: PrimeField> {
    pub deposit: Deposit<P, F>,
}

#[derive(Debug, Clone)]
pub struct PlasmaFoldExternalInputsVar<P: Config, F: PrimeField + Absorb, PG: ConfigGadget<P, F>> {
    pub deposit_var: DepositVar<P, F, PG>,
}

#[derive(Clone, Debug)]
pub struct PlasmaFoldCircuit<P: Config, F: PrimeField + Absorb, PG: ConfigGadget<P, F>> {
    mt_config: P,
    _f: PhantomData<F>,
    _f1: PhantomData<P>,
    _f2: PhantomData<PG>,
}

/// The `PlasmaFoldCircuit` implements methods to check various actions the user can take on the
/// plasma chain: deposit, transfer, receive, withdraw
impl<P: Config, F: PrimeField + Absorb, PG: ConfigGadget<P, F, Leaf = [FpVar<F>]>>
    PlasmaFoldExternalInputsVar<P, F, PG>
where
    P: Borrow<<<P as Config>::LeafHash as CRHScheme>::Parameters>
        + Borrow<<<P as Config>::TwoToOneHash as TwoToOneCRHScheme>::Parameters>
        + Clone,
{
    /// Checking the deposit consists in checking a merkle inclusion proof within a deposit block
    pub fn deposit(
        &self,
        cs: ConstraintSystemRef<F>,
        config: P,
    ) -> Result<Boolean<F>, SynthesisError> {
        let leaf_crh_params_var = <<PG as ConfigGadget<P, F>>::LeafHash as CRHSchemeGadget<
            <P as Config>::LeafHash,
            F,
        >>::ParametersVar::new_constant(
            ark_relations::ns!(cs, "leaf_crh_params"), config.clone()
        )?;

        let two_to_one_crh_params_var =
            <<PG as ConfigGadget<P, F>>::TwoToOneHash as TwoToOneCRHSchemeGadget<
                <P as Config>::TwoToOneHash,
                F,
            >>::ParametersVar::new_constant(
                ark_relations::ns!(cs, "two_to_one_crh_parameter"),
                config.clone(),
            )?;
        // let leaf_param = self.poseidon_merkle_tree_params;
        self.deposit_var.deposit_path.verify_membership(
            &leaf_crh_params_var,
            &two_to_one_crh_params_var,
            &self.deposit_var.deposit_root,
            &self.deposit_var.deposit_value,
        )
    }
}

impl<P: Config, F: PrimeField> Default for PlasmaFoldExternalInputs<P, F> {
    fn default() -> Self {
        PlasmaFoldExternalInputs {
            deposit: Deposit::default(),
        }
    }
}

impl<P: Config, F: PrimeField + Absorb, PG: ConfigGadget<P, F>>
    AllocVar<PlasmaFoldExternalInputs<P, F>, F> for PlasmaFoldExternalInputsVar<P, F, PG>
{
    fn new_variable<T: Borrow<PlasmaFoldExternalInputs<P, F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        f().and_then(|val| {
            let external_inputs: &PlasmaFoldExternalInputs<P, F> = val.borrow();
            let deposit_root_var =
                PG::InnerDigest::new_witness(ark_relations::ns!(cs, "deposit_root"), || {
                    Ok(external_inputs.deposit.deposit_root.clone())
                })?;
            let deposit_path_var =
                PathVar::<P, F, PG>::new_witness(ark_relations::ns!(cs, "deposit_path"), || {
                    Ok(external_inputs.deposit.deposit_path.clone())
                })?;
            let deposit_value = AllocVar::<[F; 2], F>::new_witness(
                ark_relations::ns!(cs, "deposit_value"),
                || Ok(external_inputs.deposit.deposit_value.clone()),
            )?;
            let deposit_var = DepositVar {
                deposit_path: deposit_path_var,
                deposit_root: deposit_root_var,
                deposit_value,
            };
            Ok(PlasmaFoldExternalInputsVar { deposit_var })
        })
    }
}

impl<
        P: Config + Clone + std::fmt::Debug,
        F: PrimeField + Absorb,
        PG: ConfigGadget<P, F, Leaf = [FpVar<F>]> + Clone + std::fmt::Debug,
    > FCircuit<F> for PlasmaFoldCircuit<P, F, PG>
where
    P: Borrow<<<P as Config>::LeafHash as CRHScheme>::Parameters>
        + Borrow<<<P as Config>::TwoToOneHash as TwoToOneCRHScheme>::Parameters>
        + Clone,
{
    type Params = P;

    type ExternalInputs = PlasmaFoldExternalInputs<P, F>;

    type ExternalInputsVar = PlasmaFoldExternalInputsVar<P, F, PG>;

    fn new(params: Self::Params) -> Result<Self, folding_schemes::Error> {
        Ok(Self {
            mt_config: params,
            _f: PhantomData::<F>,
            _f1: PhantomData::<P>,
            _f2: PhantomData::<PG>,
        })
    }

    fn state_len(&self) -> usize {
        1
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: Self::ExternalInputsVar, // inputs that are not part of the state
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // check deposit
        let deposit_is_ok = external_inputs.deposit(cs.clone(), self.mt_config.clone())?;
        deposit_is_ok.enforce_equal(&Boolean::constant(true))?;
        Ok(z_i)
    }
}
