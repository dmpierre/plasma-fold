/// Attempt to make the FCircuit generic over the merkle tree implementation.
/// Not successful for now.
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
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, prelude::Boolean};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use folding_schemes::frontend::FCircuit;

#[derive(Debug, Clone)]
pub struct Deposit<P: Config> {
    deposit_path: Path<P>,
    deposit_root: P::InnerDigest,
}

#[derive(Debug, Clone)]
pub struct DepositVar<P: Config, F: PrimeField, PG: ConfigGadget<P, F>> {
    deposit_path: PathVar<P, F, PG>,
    deposit_root: PG::InnerDigest,
    deposit_value: [FpVar<F>; 2],
}

#[derive(Debug, Clone)]
pub struct PlasmaFoldExternalInputsVar<P: Config, F: PrimeField + Absorb, PG: ConfigGadget<P, F>> {
    deposit_var: DepositVar<P, F, PG>,
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
        PG: ConfigGadget<P, F, Leaf = [FpVar<F>]> + Clone + std::fmt::Debug,
    > FCircuit<F> for PlasmaFoldCircuit<P, F, PG>
where
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
        external_inputs.deposit(cs.clone(), self.mt_config.clone())?;
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

    type F = Fr;

    impl Borrow<PoseidonConfig<Fr>> for FieldMTConfig {
        fn borrow(&self) -> &PoseidonConfig<Fr> {
            todo!()
        }
    }

    #[derive(Debug, Clone)]
    struct FieldMTConfig;
    impl Config for FieldMTConfig {
        type Leaf = [F];
        type LeafDigest = F;
        type LeafInnerDigestConverter = IdentityDigestConverter<F>;
        type InnerDigest = F;
        type LeafHash = CRH<F>;
        type TwoToOneHash = TwoToOneCRH<F>;
    }

    #[derive(Debug, Clone)]
    struct FieldMTConfigVar;
    impl ConfigGadget<FieldMTConfig, F> for FieldMTConfigVar {
        type Leaf = [FpVar<F>];
        type LeafDigest = FpVar<F>;
        type LeafInnerConverter = IdentityDigestConverter<FpVar<F>>;
        type InnerDigest = FpVar<F>;
        type LeafHash = CRHGadget<F>;
        type TwoToOneHash = TwoToOneCRHGadget<F>;
    }

    // use ark_crypto_primitives::
    pub fn test_deposit() {
        let leaf_crh_params = poseidon_canonical_config::<F>();
        let two_to_one_params = leaf_crh_params.clone();
        // let mut tree = MerkleTree::new(&leaf_crh_params, &two_to_one_params, leaves).unwrap();
        let plasma_fold_circuit =
            PlasmaFoldCircuit::<FieldMTConfig, F, FieldMTConfigVar>::new(FieldMTConfig);
    }
}
