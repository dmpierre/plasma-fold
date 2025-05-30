// accumulate the block into the block accumulator (acc)
use ark_crypto_primitives::{
    crh::{
        poseidon::constraints::CRHParametersVar, CRHSchemeGadget, TwoToOneCRHScheme,
        TwoToOneCRHSchemeGadget,
    },
    sponge::Absorb,
};
use ark_ec::CurveGroup;
use ark_r1cs_std::{alloc::AllocVar, fields::FieldVar, prelude::Boolean};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use core::cmp::Ordering;
use plasma_fold::{
    datastructures::{
        block::{constraints::BlockVar, Block},
        keypair::{constraints::PublicKeyVar, PublicKey},
        signerlist::{constraints::SignerTreeConfigGadget, SignerTreeConfig},
        transaction::{
            constraints::{TransactionTreeConfigGadget, TransactionVar},
            Transaction, TransactionTreeConfig,
        },
    },
    primitives::{
        accumulator::constraints::Accumulator,
        crh::constraints::{BlockVarCRH, PublicKeyVarCRH},
        sparsemt::{constraints::MerkleSparseTreePathVar, MerkleSparseTreePath},
    },
};
use std::marker::PhantomData;

use ark_ff::PrimeField;
use ark_r1cs_std::{eq::EqGadget, fields::fp::FpVar, groups::CurveVar};

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

pub struct UserAux<F: PrimeField + Absorb, C: CurveGroup<BaseField = F>> {
    pub transaction_inclusion_proofs: Vec<MerkleSparseTreePath<TransactionTreeConfig<C>>>,
    pub signer_pk_inclusion_proofs: Vec<MerkleSparseTreePath<SignerTreeConfig<C>>>,
    pub block: Block<F>,
    // (transaction, transaction's index within the transaction tree)
    pub transactions: Vec<(Transaction<C>, F)>,
    pub pk: PublicKey<C>,
}

pub struct UserAuxVar<F: PrimeField + Absorb, C: CurveGroup<BaseField = F>, CVar: CurveVar<C, F>> {
    pub transaction_inclusion_proofs: Vec<
        MerkleSparseTreePathVar<
            TransactionTreeConfig<C>,
            F,
            TransactionTreeConfigGadget<F, C, CVar>,
        >,
    >,
    pub signer_pk_inclusion_proofs:
        Vec<MerkleSparseTreePathVar<SignerTreeConfig<C>, F, SignerTreeConfigGadget<F, C, CVar>>>,
    pub block: BlockVar<F>,
    // (transaction, transaction's index within the transaction tree)
    pub transactions: Vec<(TransactionVar<F, C, CVar>, FpVar<F>)>,
    pub pk: PublicKeyVar<C, CVar>,
}

impl<F: PrimeField + Absorb, C: CurveGroup<BaseField = F>, CVar: CurveVar<C, F>>
    AllocVar<UserAux<F, C>, F> for UserAuxVar<F, C, CVar>
{
    fn new_variable<T: std::borrow::Borrow<UserAux<F, C>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let res = f()?;
        let cs = cs.into();
        let user_aux = res.borrow();
        let mut transaction_inclusion_proofs = Vec::new();
        for proof in user_aux.transaction_inclusion_proofs.iter() {
            let tx_inclusion_proof =
                MerkleSparseTreePathVar::new_variable(cs.clone(), || Ok(proof.clone()), mode)?;
            transaction_inclusion_proofs.push(tx_inclusion_proof);
        }

        let mut signer_pk_inclusion_proofs = Vec::new();
        for inclusion_proof in user_aux.signer_pk_inclusion_proofs.iter() {
            let signer_pk_inclusion_proof = MerkleSparseTreePathVar::new_variable(
                cs.clone(),
                || Ok(inclusion_proof.clone()),
                mode,
            )?;
            signer_pk_inclusion_proofs.push(signer_pk_inclusion_proof);
        }
        let block = BlockVar::new_variable(cs.clone(), || Ok(user_aux.block.clone()), mode)?;
        let mut transactions = Vec::new();
        for (tx, index) in user_aux.transactions.iter() {
            let tx_var = TransactionVar::new_variable(cs.clone(), || Ok(tx), mode)?;
            let index = FpVar::new_variable(cs.clone(), || Ok(index), mode)?;
            transactions.push((tx_var, index));
        }
        let pk = PublicKeyVar::new_variable(cs.clone(), || Ok(user_aux.pk), mode)?;
        Ok(Self {
            transaction_inclusion_proofs,
            signer_pk_inclusion_proofs,
            block,
            transactions,
            pk,
        })
    }
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
        aux: UserAuxVar<F, C, CVar>,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // z_i is (balance, nonce, pk, acc, n_processed_tx)
        let (
            mut balance_t_plus_1,
            mut nonce_t_plus_1,
            pk_hash,
            mut acc_t_plus_1,
            mut prev_block_hash,
            mut prev_block_number,
            mut prev_processed_tx_index,
        ) = (
            z_i[0].clone(),
            z_i[1].clone(),
            z_i[2].clone(),
            z_i[3].clone(),
            z_i[4].clone(),
            z_i[5].clone(),
            z_i[6].clone(),
        );

        // ensure correct pk is provided in aux inputs
        let computed_pk_hash = PublicKeyVarCRH::evaluate(&self.pp, &aux.pk)?;
        computed_pk_hash.enforce_equal(&pk_hash)?;

        // compute block hash and update accumulator value
        let block_hash = BlockVarCRH::evaluate(&self.pp, &aux.block)?;
        acc_t_plus_1 = A::update(&self.acc_pp, &acc_t_plus_1, &block_hash)?;

        // ensure the current processed block number is equal or greater than the previous block
        let _ = &prev_block_number.enforce_cmp(&aux.block.number, Ordering::Less, true)?;

        // TXs PROCESSING
        // if prev_block_hash == currently_processed_block -> currently processed tx index should
        // be equal or greater than the next authorized tx index
        let processing_same_block = block_hash.is_eq(&prev_block_hash)?;

        for (
            ((transaction, transaction_index), transaction_inclusion_proof),
            signer_pk_inclusion_proof,
        ) in aux
            .transactions
            .iter()
            .zip(aux.transaction_inclusion_proofs)
            .zip(aux.signer_pk_inclusion_proofs)
        {
            // if we are processing the same block, the previously processed transaction index should
            // be lower than the currently processed transaction
            let prev_tx_index_is_lower =
                &prev_processed_tx_index.is_cmp(&transaction_index, Ordering::Less, true)?;
            prev_tx_index_is_lower
                .conditional_enforce_equal(&Boolean::Constant(true), &processing_same_block)?;

            // check that tx is in tx tree
            transaction_inclusion_proof.check_membership_with_index(
                &self.pp,
                &self.pp,
                &aux.block.tx_tree_root,
                &transaction,
                &transaction_index,
            )?;

            let transaction_signer = transaction.get_signer();

            // check that tx signer is in the signer tree
            signer_pk_inclusion_proof.check_membership(
                cs.clone(),
                &self.pp,
                &self.pp,
                &aux.block.signer_tree_root,
                &transaction_signer,
            )?;

            // increment user nonce by 1 if the tx signer is the user
            let signer_is_user = aux.pk.key.is_eq(&transaction_signer.key)?;
            nonce_t_plus_1 += &signer_is_user.into();

            // decrease user balance if sender is user
            for input in transaction.inputs.iter() {
                let sender_is_user = input.pk.key.is_eq(&aux.pk.key)?;
                balance_t_plus_1 -= &input.amount * &sender_is_user.into();
            }

            // increase user balance if receiver is user
            for output in transaction.outputs.iter() {
                let receiver_is_user = output.pk.key.is_eq(&aux.pk.key)?;
                balance_t_plus_1 += &output.amount * &receiver_is_user.into();
            }

            prev_processed_tx_index = transaction_index + FpVar::constant(F::one());
        }

        // set the new processed transaction index to the currently processed transaction
        // and set new block hash to the currently processed block
        prev_block_hash = block_hash;
        prev_block_number = aux.block.number;

        Ok([
            balance_t_plus_1,
            nonce_t_plus_1,
            pk_hash,
            acc_t_plus_1,
            prev_block_hash,
            prev_block_number,
            prev_processed_tx_index,
        ]
        .to_vec())
    }
}
