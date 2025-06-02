use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::{
        poseidon::constraints::{CRHGadget, CRHParametersVar},
        sha256::constraints::UnitVar,
        CRHSchemeGadget,
    },
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ec::CurveGroup;
use ark_ff::{PrimeField, Zero};
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    groups::CurveVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use folding_schemes::frontend::FCircuit;
use plasma_fold::{
    datastructures::{
        keypair::{
            constraints::{PublicKeyVar, SignatureVar},
            PublicKey,
        },
        signerlist::{constraints::SignerTreeConfigGadget, SignerTreeConfig},
        transaction::{
            constraints::{TransactionTreeConfigGadget, TransactionVar},
            Transaction, TransactionTreeConfig,
        },
        utxo::{
            constraints::{UTXOTreeConfigGadget, UTXOVar},
            UTXOTree, UTXOTreeConfig, UTXO,
        },
        TX_IO_SIZE,
    },
    primitives::{
        accumulator::{
            constraints::{Accumulator, Sha256AccumulatorVar},
            Sha256Accumulator,
        },
        sparsemt::constraints::{MerkleSparseTreePathVar, MerkleSparseTreeTwoPathsVar},
    },
};

#[derive(Clone, Debug)]
pub struct AggregatorCircuit<C: CurveGroup<BaseField: PrimeField>, CVar> {
    _c: PhantomData<(C, CVar)>,
    poseidon_config: PoseidonConfig<C::BaseField>,
    contract_pk: PublicKey<C>,
}

#[derive(Clone, Debug, Default)]
pub struct AggregatorCircuitInputs<C: CurveGroup> {
    tx: Transaction<C>,
}

#[derive(Clone, Debug)]
pub struct AggregatorCircuitInputsVar<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    CVar: CurveVar<C, C::BaseField>,
> {
    tx: TransactionVar<C::BaseField, C, CVar>,
    tx_tree_update_proof: MerkleSparseTreeTwoPathsVar<
        TransactionTreeConfig<C>,
        C::BaseField,
        TransactionTreeConfigGadget<C::BaseField, C, CVar>,
    >,
    utxo_tree_deletion_proofs: [MerkleSparseTreeTwoPathsVar<
        UTXOTreeConfig<C>,
        C::BaseField,
        UTXOTreeConfigGadget<C::BaseField, C, CVar>,
    >; TX_IO_SIZE],
    utxo_tree_deletion_positions: [FpVar<C::BaseField>; TX_IO_SIZE],
    utxo_tree_addition_proofs: [MerkleSparseTreeTwoPathsVar<
        UTXOTreeConfig<C>,
        C::BaseField,
        UTXOTreeConfigGadget<C::BaseField, C, CVar>,
    >; TX_IO_SIZE],
    utxo_tree_addition_positions: [FpVar<C::BaseField>; TX_IO_SIZE],
    signer_tree_update_proof: MerkleSparseTreeTwoPathsVar<
        SignerTreeConfig<C>,
        C::BaseField,
        SignerTreeConfigGadget<C::BaseField, C, CVar>,
    >,
    sender_pk: PublicKeyVar<C, CVar>,
    signature: SignatureVar<C::BaseField>,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>
    AllocVar<AggregatorCircuitInputs<C>, C::BaseField> for AggregatorCircuitInputsVar<C, CVar>
{
    fn new_variable<T: std::borrow::Borrow<AggregatorCircuitInputs<C>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        todo!()
    }
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>
    FCircuit<C::BaseField> for AggregatorCircuit<C, CVar>
{
    type Params = (PoseidonConfig<C::BaseField>, PublicKey<C>);

    type ExternalInputs = AggregatorCircuitInputs<C>;

    type ExternalInputsVar = AggregatorCircuitInputsVar<C, CVar>;

    fn new((poseidon_config, contract_pk): Self::Params) -> Result<Self, folding_schemes::Error> {
        Ok(Self {
            _c: PhantomData,
            poseidon_config,
            contract_pk,
        })
    }

    fn state_len(&self) -> usize {
        todo!()
    }

    fn generate_step_constraints(
        // this method uses self, so that each FCircuit implementation (and different frontends)
        // can hold a state if needed to store data to generate the constraints.
        &self,
        cs: ConstraintSystemRef<C::BaseField>,
        _: usize,
        z_i: Vec<FpVar<C::BaseField>>,
        external_inputs: Self::ExternalInputsVar, // inputs that are not part of the state
    ) -> Result<Vec<FpVar<C::BaseField>>, SynthesisError> {
        let pp = CRHParametersVar::new_constant(cs.clone(), self.poseidon_config.clone())?;
        let contract_pk = PublicKeyVar::<C, CVar>::new_constant(cs.clone(), &self.contract_pk)?;

        let step = &z_i[0];
        let mut utxo_root = z_i[1].clone();
        let mut tx_root = z_i[2].clone();
        let mut signer_root = z_i[3].clone();
        let signer_acc = z_i[4].clone();

        let AggregatorCircuitInputsVar {
            tx,
            tx_tree_update_proof,
            utxo_tree_addition_proofs,
            utxo_tree_addition_positions,
            utxo_tree_deletion_proofs,
            utxo_tree_deletion_positions,
            signer_tree_update_proof,
            sender_pk,
            signature,
        } = external_inputs;

        tx.enforce_valid(Some(sender_pk.clone()), None)?;

        let (tx_root_old, tx_root_new) = tx_tree_update_proof.update_root(
            &pp,
            &pp,
            &TransactionVar::new_constant(cs.clone(), Transaction::default())?,
            &tx,
            step,
        )?;
        tx_root_old.enforce_equal(&tx_root)?;
        tx_root = tx_root_new;

        // TODO: block tree update

        let signature_validity = sender_pk.is_signature_valid::<32>(
            &pp,
            &TryInto::<Vec<_>>::try_into(&tx)?,
            signature,
        )?;
        let sender_is_contract = sender_pk.key.is_eq(&contract_pk.key)?;
        let tx_validity = signature_validity ^ sender_is_contract;

        for i in 0..TX_IO_SIZE {
            // TODO: deposit
            let (utxo_root_old, utxo_root_new) = utxo_tree_deletion_proofs[i].update_root(
                &pp,
                &pp,
                &tx.inputs[i],
                &UTXOVar::new_constant(cs.clone(), UTXO::default())?,
                &utxo_tree_deletion_positions[i],
            )?;
            utxo_root.conditional_enforce_equal(&utxo_root_old, &tx_validity)?;
            utxo_root = tx_validity.select(&utxo_root_new, &utxo_root)?;
        }
        for i in 0..TX_IO_SIZE {
            // TODO: withdrawal
            let (utxo_root_old, utxo_root_new) = utxo_tree_addition_proofs[i].update_root(
                &pp,
                &pp,
                &UTXOVar::new_constant(cs.clone(), UTXO::default())?,
                &tx.inputs[i],
                &utxo_tree_addition_positions[i],
            )?;
            utxo_root.conditional_enforce_equal(&utxo_root_old, &tx_validity)?;
            utxo_root = tx_validity.select(&utxo_root_new, &utxo_root)?;
        }
        let (signer_root_old, signer_root_new) = signer_tree_update_proof.update_root(
            &pp,
            &pp,
            &PublicKeyVar::new_constant(cs.clone(), PublicKey::default())?,
            &sender_pk,
            step,
        )?;
        signer_root_old.conditional_enforce_equal(&signer_root, &tx_validity)?;
        signer_root = tx_validity.select(&signer_root_new, &signer_root)?;

        let signer_acc = Sha256AccumulatorVar::update(
            &UnitVar::new_constant(cs.clone(), ())?,
            &signer_acc,
            &tx_validity.select(
                // TODO: use SHA256 as well for this inner hash?
                &CRHGadget::evaluate(&pp, &{
                    let mut xy = sender_pk.key.to_constraint_field()?;
                    xy.pop();
                    xy.push(tx.nonce.clone());
                    xy
                })?,
                &FpVar::zero(),
            )?,
        )?;

        Ok(vec![
            step + FpVar::one(),
            tx_root,
            utxo_root,
            signer_root,
            signer_acc,
        ])
    }
}
