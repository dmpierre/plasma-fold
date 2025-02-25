use std::{borrow::Borrow, marker::PhantomData};

use ark_bn254::Fr;
use ark_crypto_primitives::{
    crh::{
        poseidon::{
            constraints::{CRHGadget, TwoToOneCRHGadget},
            TwoToOneCRH, CRH,
        },
        CRHScheme, CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget,
    },
    merkle_tree::{
        constraints::{ConfigGadget, PathVar},
        Config, IdentityDigestConverter, Path,
    },
    sponge::Absorb,
};

use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, prelude::Boolean};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use folding_schemes::frontend::FCircuit;

#[derive(Debug, Clone)]
struct PoseidonMTConfig;
impl Config for PoseidonMTConfig {
    type Leaf = [Fr];
    type LeafDigest = Fr;
    type LeafInnerDigestConverter = IdentityDigestConverter<Fr>;
    type InnerDigest = Fr;
    type LeafHash = CRH<Fr>;
    type TwoToOneHash = TwoToOneCRH<Fr>;
}

#[derive(Debug, Clone)]
struct PoseidonMTConfigVar;
impl ConfigGadget<PoseidonMTConfig, Fr> for PoseidonMTConfig {
    type Leaf = [FpVar<Fr>];
    type LeafDigest = FpVar<Fr>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<Fr>>;
    type InnerDigest = FpVar<Fr>;
    type LeafHash = CRHGadget<Fr>;
    type TwoToOneHash = TwoToOneCRHGadget<Fr>;
}

#[derive(Debug, Clone)]
pub struct Deposit {
    deposit_path: Path<PoseidonMTConfig>,
    deposit_root: <PoseidonMTConfig as Config>::InnerDigest,
}

#[derive(Debug, Clone)]
pub struct DepositVar {
    deposit_path: PathVar<PoseidonMTConfig, Fr, PoseidonMTConfig>,
    deposit_root: <PoseidonMTConfig as ConfigGadget<PoseidonMTConfig, Fr>>::InnerDigest,
    deposit_value: <PoseidonMTConfig as ConfigGadget<PoseidonMTConfig, Fr>>::Leaf,
}

#[derive(Debug, Clone)]
pub struct PlasmaFoldExternalInputsVar {
    deposit_var: DepositVar,
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
impl PlasmaFoldExternalInputsVar {
    /// Checking the deposit consists in checking a merkle inclusion proof within a deposit block
    pub fn deposit(
        &self,
        cs: ConstraintSystemRef<Fr>,
        config: PoseidonMTConfig,
        leaf_crh_params: <<PoseidonMTConfig as ConfigGadget<PoseidonMTConfig, Fr>>::LeafHash as CRHSchemeGadget<
            <PoseidonMTConfig as Config>::LeafHash,
            Fr,
        >>::ParametersVar,
        two_to_one_crh_params_var: <<PG as ConfigGadget<P, F>>::TwoToOneHash as TwoToOneCRHSchemeGadget<
                <P as Config>::TwoToOneHash,
                F,
            >>::ParametersVar,
    ) -> Result<Boolean<F>, SynthesisError> {
        // let leaf_param = self.poseidon_merkle_tree_params;
        //self.deposit_var.deposit_path.verify_membership(
        //    &leaf_crh_params_var,
        //    &two_to_one_crh_params_var,
        //    &self.deposit_var.deposit_root,
        //    &self.deposit_var.deposit_value,
        //)?;
        todo!();
    }
}

#[derive(Debug, Clone)]
pub struct PlasmaFoldExternalInputs<P: Config> {
    deposit: Deposit<P>,
}

impl<P: Config> Default for PlasmaFoldExternalInputs<P> {
    fn default() -> Self {
        todo!()
    }
}

impl<P: Config, F: PrimeField + Absorb, PG: ConfigGadget<P, F>>
    AllocVar<PlasmaFoldExternalInputs<P>, F> for PlasmaFoldExternalInputsVar<P, F, PG>
where
    PG::Leaf: Clone,
{
    fn new_variable<T: Borrow<PlasmaFoldExternalInputs<P>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        todo!();
    }
}

impl<
        P: Config + Clone + std::fmt::Debug,
        F: PrimeField + Absorb,
        PG: ConfigGadget<P, F> + Clone + std::fmt::Debug,
    > FCircuit<F> for PlasmaFoldCircuit<P, F, PG>
where
    PG::Leaf: Clone,
    P: Borrow<<<P as Config>::LeafHash as CRHScheme>::Parameters>
        + Borrow<<<P as Config>::TwoToOneHash as TwoToOneCRHScheme>::Parameters>
        + Clone,
{
    type Params = P;

    // [balance, n_deposits, n_transfers, n_receives, n_withdrawals]
    type ExternalInputs = PlasmaFoldExternalInputs<P>;

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
        // this method uses self, so that each FCircuit implementation (and different frontends)
        // can hold a state if needed to store data to generate the constraints.
        &self,
        cs: ConstraintSystemRef<F>,
        i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: Self::ExternalInputsVar, // inputs that are not part of the state
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let leaf_crh_params_var = <<PG as ConfigGadget<P, F>>::LeafHash as CRHSchemeGadget<
            <P as Config>::LeafHash,
            F,
        >>::ParametersVar::new_constant(
            ark_relations::ns!(cs, "leaf_crh_params"),
            self.mt_config.clone(),
        )?;

        let two_to_one_crh_params_var =
            <<PG as ConfigGadget<P, F>>::TwoToOneHash as TwoToOneCRHSchemeGadget<
                <P as Config>::TwoToOneHash,
                F,
            >>::ParametersVar::new_constant(
                ark_relations::ns!(cs, "two_to_one_crh_parameter"),
                self.mt_config.clone(),
            )?;
        // external_inputs.deposit(cs.clone(), self.mt_config.clone())?;
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::fr::Fr;
    use ark_crypto_primitives::crh::poseidon::constraints::CRHGadget;
    use ark_crypto_primitives::crh::poseidon::constraints::TwoToOneCRHGadget;
    use ark_crypto_primitives::crh::poseidon::TwoToOneCRH;
    use ark_crypto_primitives::crh::poseidon::CRH;
    use ark_crypto_primitives::merkle_tree::constraints::ConfigGadget;
    use ark_crypto_primitives::merkle_tree::{Config, IdentityDigestConverter};
    use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
    use ark_r1cs_std::fields::fp::FpVar;
    use folding_schemes::{frontend::FCircuit, transcript::poseidon::poseidon_canonical_config};
    use std::borrow::Borrow;

    use super::PlasmaFoldCircuit;

    // use ark_crypto_primitives::
    pub fn test_deposit() {
        let leaf_crh_params = poseidon_canonical_config::<F>();
        let two_to_one_params = leaf_crh_params.clone();
        // let mut tree = MerkleTree::new(&leaf_crh_params, &two_to_one_params, leaves).unwrap();
        //let plasma_fold_circuit =
        //    PlasmaFoldCircuit::<FieldMTConfig, F, FieldMTConfigVar>::new(FieldMTConfig);
    }
}
