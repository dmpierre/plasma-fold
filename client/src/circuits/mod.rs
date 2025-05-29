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
    F: PrimeField + Absorb,
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
    pp: CRHParametersVar<F>,
}

impl<
        F: PrimeField + Absorb,
        C: CurveGroup,
        CVar: CurveVar<C, F>,
        H: TwoToOneCRHScheme,
        T: TwoToOneCRHSchemeGadget<H, F>,
        A: Accumulator<F, H, T>,
    > UserCircuit<F, C, CVar, H, T, A>
{
    pub fn new(acc_pp: T::ParametersVar, pp: CRHParametersVar<F>) -> Self {
        UserCircuit {
            _a: PhantomData,
            _f: PhantomData,
            _c: PhantomData,
            _cvar: PhantomData,
            acc_pp,
            pp,
        }
    }
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
    // (transaction, transaction's index within the transaction tree)
    pub transaction: (TransactionVar<F, C, CVar>, FpVar<F>),
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

        let (mut balance_t_plus_1, mut nonce_t_plus_1, mut acc_t_plus_1) =
            (z_i[0].clone(), z_i[1].clone(), z_i[2].clone());

        // compute block hash and update accumulator value
        let block_hash = BlockVarCRH::evaluate(&self.pp, &aux.block)?;
        acc_t_plus_1 = A::update(&self.acc_pp, &acc_t_plus_1, &block_hash)?;

        // TODO: enforce j > pos
        let pos = FpVar::new_constant(cs.clone(), F::from(-1))?;

        // check that tx is in tx tree
        aux.tx_inclusion_proof.check_membership_with_index(
            &self.pp,
            &self.pp,
            &aux.block.tx_tree_root,
            &aux.transaction.0,
            &aux.transaction.1,
        )?;

        // check that tx signer is in the signer tree
        let tx_signer = aux.transaction.0.get_signer();
        aux.signer_pk_inclusion_proof.check_membership(
            cs.clone(),
            &self.pp,
            &self.pp,
            &aux.block.signer_tree_root,
            &tx_signer,
        )?;

        // increment user nonce by 1 if the tx signer is the user
        let signer_is_user = aux.pk.key.is_eq(&tx_signer.key)?;
        nonce_t_plus_1 += &signer_is_user.into();

        // process transaction inputs and outputs
        for input in aux.transaction.0.inputs {
            input.pk.key.enforce_equal(&aux.pk.key)?;
            balance_t_plus_1 += &input.amount;
        }

        for output in aux.transaction.0.outputs {
            let receiver_is_user = output.pk.key.is_eq(&aux.pk.key)?;
            balance_t_plus_1 += output.amount * &receiver_is_user.into();
        }

        Ok([balance_t_plus_1, nonce_t_plus_1, acc_t_plus_1].to_vec())
    }
}
