// accumulate the block into the block accumulator (acc)
//
use ark_crypto_primitives::{
    crh::{poseidon::constraints::CRHParametersVar, CRHSchemeGadget},
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ec::CurveGroup;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use plasma_fold::{
    datastructures::{
        block::constraints::BlockVar,
        signerlist::{constraints::SignerTreeConfigGadget, SignerTreeConfig},
        transaction::{
            constraints::{TransactionTreeConfigGadget, TransactionVar},
            TransactionTreeConfig,
        },
    },
    primitives::{
        accumulator::constraints::{PoseidonAccumulatorVar, Sha256AccumulatorVar},
        crh::constraints::{BlockVarCRH, TransactionVarCRH},
        sparsemt::constraints::MerkleSparseTreePathVar,
    },
};
use std::marker::PhantomData;

use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, groups::CurveVar};

pub struct UserCircuit<F: PrimeField, C: CurveGroup, CVar: CurveVar<C, F>> {
    _f: PhantomData<F>,
    _c: PhantomData<C>,
    _cvar: PhantomData<CVar>,
    pp: PoseidonConfig<F>,
}

pub struct UserAux<F: PrimeField + Absorb, C: CurveGroup<BaseField = F>, CVar: CurveVar<C, F>> {
    pub tx_inclusion_proof: MerkleSparseTreePathVar<
        TransactionTreeConfig<C>,
        F,
        TransactionTreeConfigGadget<F, C, CVar>,
    >,
    pub signer_pk_inclusion_proof:
        MerkleSparseTreePathVar<SignerTreeConfig<C>, F, SignerTreeConfigGadget<F, C, CVar>>,
    pub block: BlockVar<F>,
    pub transaction: TransactionVar<F, C, CVar>,
}

impl<F: PrimeField + Absorb, C: CurveGroup<BaseField = F>, CVar: CurveVar<C, F>>
    UserCircuit<F, C, CVar>
{
    pub fn update_balance(
        &self,
        cs: ConstraintSystemRef<F>,
        z_i: Vec<FpVar<F>>,
        aux: UserAux<F, C, CVar>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // z_i is (balance, nonce, acc)
        let pp = CRHParametersVar::new_constant(cs.clone(), self.pp.clone())?;
        let (mut balance_t_plus_1, mut nonce_t_plus_1, mut acc_t_plus_1) =
            (z_i[0].clone(), z_i[1].clone(), z_i[2].clone());

        // compute block hash and update accumulator value
        let block_hash = BlockVarCRH::evaluate(&pp, &aux.block)?;
        acc_t_plus_1 = PoseidonAccumulatorVar::update(&pp, &acc_t_plus_1, &block_hash)?;

        let pos = FpVar::new_constant(cs.clone(), F::from(-1))?;

        // TODO: enforce j > pos

        // check that tx is in tx tree
        let tx = aux.transaction;
        let tx_inclusion_proof = aux.tx_inclusion_proof;
        let tx_tree_root = aux.block.tx_tree_root;

        // TODO: does not enforce index consistency, should be ok?
        tx_inclusion_proof.check_membership(cs, &pp, &pp, &tx_tree_root, &tx)?;

        Ok([acc_t_plus_1].to_vec())
    }
}
