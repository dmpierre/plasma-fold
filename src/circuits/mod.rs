use std::{borrow::Borrow, marker::PhantomData};

use ark_crypto_primitives::{
    crh::{CRHScheme, CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget},
    merkle_tree::{constraints::ConfigGadget, Config},
    sponge::Absorb,
};

use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, prelude::Boolean};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use block::{Block, BlockVar};
use deposit::{Deposit, DepositVar};
use folding_schemes::frontend::FCircuit;

pub mod block;
pub mod deposit;

/// PlasmaFold private inputs consists in
/// `balance`, `transfer_flag` (can not be activated at the same time as the deposit flag, since a
/// user can not make a deposit and a transfer in the same block), `transfer_proof`, `update_flag`, `update_proof`,
/// `withdraw_flag`, `withdraw_proof`
#[derive(Debug, Clone)]
pub struct PlasmaFoldExternalInputs<P: Config, F: PrimeField> {
    pub balance: F, // balance of the user on the plasma fold chain
    // deposit witness (merkle proof of inclusion within the deposit block)
    pub deposit: Deposit<P, F>,
    // block, containing different trees
    pub block: Block<P>,
}

#[derive(Debug, Clone)]
pub struct PlasmaFoldExternalInputsVar<P: Config, F: PrimeField + Absorb, PG: ConfigGadget<P, F>> {
    pub balance: FpVar<F>,
    pub deposit_var: DepositVar<P, F, PG>,
    pub block_var: BlockVar<P, F, PG>,
}

#[derive(Clone, Debug)]
pub struct PlasmaFoldCircuit<P: Config, F: PrimeField + Absorb, PG: ConfigGadget<P, F>> {
    mt_config: P,
    _f: PhantomData<F>,
    _f1: PhantomData<P>,
    _f2: PhantomData<PG>,
}

/// The `PlasmaFoldExternalInputsVar` struct implements methods to check various actions the user can take on the
/// plasma chain: deposit, transfer, receive, withdraw
/// For now, it uses the same hash for both computing merkle trees and block hashes
/// TODO: be generic over the CRH used as well
impl<
        P: Config,
        F: PrimeField + Absorb,
        PG: ConfigGadget<P, F, Leaf = [FpVar<F>], InnerDigest = FpVar<F>>,
    > PlasmaFoldExternalInputsVar<P, F, PG>
where
    P: Borrow<<<P as Config>::LeafHash as CRHScheme>::Parameters>
        + Borrow<<<P as Config>::TwoToOneHash as TwoToOneCRHScheme>::Parameters>
        + Clone,
{
    /// Compute block hash
    pub fn compute_block_hash(
        &self,
        cs: ConstraintSystemRef<F>,
        config: P,
        prev_block_hash: FpVar<F>,
    ) -> Result<<PG::LeafHash as CRHSchemeGadget<P::LeafHash, F>>::OutputVar, SynthesisError> {
        let crh_parameters_var = <<PG as ConfigGadget<P, F>>::LeafHash as CRHSchemeGadget<
            <P as Config>::LeafHash,
            F,
        >>::ParametersVar::new_constant(
            ark_relations::ns!(cs, "crh_params"), config.clone()
        )?;
        <PG::LeafHash as CRHSchemeGadget<P::LeafHash, F>>::evaluate(
            &crh_parameters_var,
            &[
                prev_block_hash.clone(),
                self.block_var.deposit_tree_root.clone(),
                self.block_var.transaction_tree_root.clone(),
                self.block_var.withdrawal_tree_root.clone(),
            ],
        )
    }

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
            block: Block::default(),
            balance: F::default(),
        }
    }
}

impl<P: Config, F: PrimeField + Absorb, PG: ConfigGadget<P, F>>
    AllocVar<PlasmaFoldExternalInputs<P, F>, F> for PlasmaFoldExternalInputsVar<P, F, PG>
{
    // TODO: impl AllocVar for DepositVar
    // TODO: the deposit root is duplicated, remove this duplication
    fn new_variable<T: Borrow<PlasmaFoldExternalInputs<P, F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        f().and_then(|val| {
            let external_inputs: &PlasmaFoldExternalInputs<P, F> = val.borrow();
            let balance = FpVar::<F>::new_witness(ark_relations::ns!(cs, "balance"), || {
                Ok(external_inputs.balance)
            })?;
            let deposit_var = DepositVar::new_witness(ark_relations::ns!(cs, "deposit"), || {
                Ok(&external_inputs.deposit)
            })?;
            let block_var = BlockVar::new_witness(ark_relations::ns!(cs, "block"), || {
                Ok(&external_inputs.block)
            })?;
            Ok(PlasmaFoldExternalInputsVar {
                block_var,
                deposit_var,
                balance,
            })
        })
    }
}

impl<
        P: Config + Clone + std::fmt::Debug, // for computing trees
        F: PrimeField + Absorb,
        PG: ConfigGadget<P, F, Leaf = [FpVar<F>], InnerDigest = FpVar<F>, LeafDigest = FpVar<F>>
            + Clone
            + std::fmt::Debug,
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

    /// the IVC state consists in `[prev_block, nonce]` and indicate whether the account is up to
    /// date with the latest block and the rollup contract stored nonce.
    fn state_len(&self) -> usize {
        2
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: Self::ExternalInputsVar, // inputs that are not part of the state
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // COMPUTE NEXT BLOCK HASH
        let new_block_hash = external_inputs.compute_block_hash(
            cs.clone(),
            self.mt_config.clone(),
            z_i[0].clone(),
        )?;

        // DEPOSIT
        // 1. Check that the deposit logic is correct
        // (deposit is ok and deposit flag is true) or (the deposit is not ok and the deposit flag is false)
        // This means that we want to ensure that deposit_is_ok == deposit_flag
        let deposit_flag = &external_inputs.deposit_var.deposit_flag;
        let deposit_is_ok = external_inputs.deposit(cs.clone(), self.mt_config.clone())?;
        deposit_is_ok.enforce_equal(deposit_flag)?;

        //  2. update balance accordingly
        //  TODO: update balance accordingly using deposit flag. When false, balance doesn't get
        //  updated, otherwise, when deposit is correct and flag is true, can update balance

        // TRANSFER
        Ok(Vec::from([new_block_hash, z_i[1].clone()]))
    }
}
