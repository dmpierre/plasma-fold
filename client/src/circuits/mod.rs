// accumulate the block into the block accumulator (acc)
//
use ark_crypto_primitives::{
    crh::{
        poseidon::constraints::CRHParametersVar, CRHSchemeGadget, TwoToOneCRHScheme,
        TwoToOneCRHSchemeGadget,
    },
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ec::CurveGroup;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use plasma_fold::{
    datastructures::{
        block::constraints::BlockVar,
        keypair::constraints::PublicKeyVar,
        signerlist::{constraints::SignerTreeConfigGadget, SignerTreeConfig},
        transaction::{
            constraints::{TransactionTreeConfigGadget, TransactionVar},
            TransactionTreeConfig,
        },
    },
    primitives::{
        accumulator::constraints::Accumulator, crh::constraints::BlockVarCRH,
        sparsemt::constraints::MerkleSparseTreePathVar,
    },
};
use std::marker::PhantomData;

use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, groups::CurveVar};

pub struct UserCircuit<
    F: PrimeField,
    C: CurveGroup,
    CVar: CurveVar<C, F>,
    H: TwoToOneCRHScheme,
    T: TwoToOneCRHSchemeGadget<H, F>,
    A: Accumulator<F, H, T>,
> {
    _a: PhantomData<A>,
    _f: PhantomData<F>,
    _c: PhantomData<C>,
    _cvar: PhantomData<CVar>,
    acc_pp: T::ParametersVar, // public parameters for the accumulator might not be poseidon
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
    pub pk: PublicKeyVar<C, CVar>,
}

impl<
        F: PrimeField + Absorb,
        C: CurveGroup<BaseField = F>,
        CVar: CurveVar<C, F>,
        H: TwoToOneCRHScheme,
        T: TwoToOneCRHSchemeGadget<H, F>,
        A: Accumulator<F, H, T>,
    > UserCircuit<F, C, CVar, H, T, A>
{
    pub fn update_balance(
        &self,
        cs: ConstraintSystemRef<F>,
        z_i: Vec<FpVar<F>>,
        aux: UserAux<F, C, CVar>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // z_i is (balance, nonce, acc)
        let pp = CRHParametersVar::new_constant(cs.clone(), &self.pp)?;

        let (mut balance_t_plus_1, mut nonce_t_plus_1, mut acc_t_plus_1) =
            (z_i[0].clone(), z_i[1].clone(), z_i[2].clone());

        // compute block hash and update accumulator value
        let block_hash = BlockVarCRH::evaluate(&pp, &aux.block)?;
        acc_t_plus_1 = A::update(&self.acc_pp, &acc_t_plus_1, &block_hash)?;

        // TODO: enforce j > pos
        let pos = FpVar::new_constant(cs.clone(), F::from(-1))?;

        // check that tx is in tx tree
        // TODO: does not enforce index consistency, should be ok?
        aux.tx_inclusion_proof.check_membership(
            cs.clone(),
            &pp,
            &pp,
            &aux.block.tx_tree_root,
            &aux.transaction,
        )?;

        // check that tx signer is in the signer tree
        let tx_signer = aux.transaction.get_signer();
        aux.signer_pk_inclusion_proof.check_membership(
            cs.clone(),
            &pp,
            &pp,
            &aux.block.signer_tree_root,
            &tx_signer,
        )?;

        // increment user nonce by 1 if the tx signer is the user
        let signer_is_user = aux.pk.key.is_eq(&tx_signer.key)?;
        nonce_t_plus_1 += &signer_is_user.into();

        // process transaction inputs and outputs
        for input in aux.transaction.inputs {
            input.pk.key.enforce_equal(&aux.pk.key)?;
            balance_t_plus_1 += &input.amount;
        }

        for output in aux.transaction.outputs {
            let receiver_is_user = output.pk.key.is_eq(&aux.pk.key)?;
            balance_t_plus_1 += output.amount * &receiver_is_user.into();
        }

        Ok([balance_t_plus_1, nonce_t_plus_1, acc_t_plus_1].to_vec())
    }
}
