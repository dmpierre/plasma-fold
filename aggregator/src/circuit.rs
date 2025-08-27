use std::{array, marker::PhantomData};

use ark_crypto_primitives::{
    crh::{poseidon::constraints::CRHParametersVar, sha256::constraints::Sha256Gadget},
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ec::CurveGroup;
#[allow(unused_imports)]
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    convert::{ToBytesGadget, ToConstraintFieldGadget},
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    groups::CurveVar,
    prelude::Boolean,
    uint8::UInt8,
    GR1CSVar,
};
use ark_relations::gr1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use folding_schemes::frontend::FCircuit;
use plasma_fold::{
    datastructures::{
        keypair::{
            constraints::{PublicKeyVar, SignatureVar},
            PublicKey, Signature,
        },
        signerlist::{constraints::SignerTreeConfigGadget, SignerTreeConfig},
        transaction::{
            constraints::{TransactionTreeConfigGadget, TransactionVar},
            Transaction, TransactionTreeConfig,
        },
        utxo::{
            constraints::{UTXOTreeConfigGadget, UTXOVar},
            UTXOTreeConfig, UTXO,
        },
        TX_IO_SIZE,
    },
    primitives::sparsemt::{constraints::MerkleSparseTreeTwoPathsVar, MerkleSparseTreeTwoPaths},
};

pub trait ToNBitsGadget<F: PrimeField> {
    fn to_n_bits(&self, n: usize) -> Result<Vec<Boolean<F>>, SynthesisError>;
}

impl<F: PrimeField> ToNBitsGadget<F> for FpVar<F> {
    fn to_n_bits(&self, n: usize) -> Result<Vec<Boolean<F>>, SynthesisError> {
        let cs = self.cs();

        let bits = self.value().unwrap_or_default().into_bigint().to_bits_le();

        let bits = Vec::new_variable_with_inferred_mode(cs, || Ok(&bits[..n]))?;

        Boolean::le_bits_to_fp(&bits)?.enforce_equal(self)?;

        Ok(bits)
    }
}

#[derive(Clone, Debug)]
pub struct AggregatorCircuit<C: CurveGroup<BaseField: PrimeField>, CVar, const B: usize> {
    _c: PhantomData<(C, CVar)>,
    poseidon_config: PoseidonConfig<C::BaseField>,
    contract_pk: PublicKey<C>,

    transfer_only: bool,
}

#[derive(Clone, Debug, Default)]
pub struct AggregatorCircuitInputs<C: CurveGroup<BaseField: PrimeField + Absorb>> {
    pub tx: Transaction<C>,
    pub tx_tree_update_proof: MerkleSparseTreeTwoPaths<TransactionTreeConfig<C>>,
    pub utxo_tree_deletion_proofs: [MerkleSparseTreeTwoPaths<UTXOTreeConfig<C>>; TX_IO_SIZE],
    pub utxo_tree_deletion_positions: [C::BaseField; TX_IO_SIZE],
    pub utxo_tree_addition_proofs: [MerkleSparseTreeTwoPaths<UTXOTreeConfig<C>>; TX_IO_SIZE],
    pub utxo_tree_addition_positions: [C::BaseField; TX_IO_SIZE],
    pub signer_tree_update_proof: MerkleSparseTreeTwoPaths<SignerTreeConfig<C>>,
    pub sender_pk: PublicKey<C>,
    pub signature: Signature<C::ScalarField>,
}

#[derive(Clone, Debug)]
pub struct BatchedAggregatorCircuitInputs<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    const B: usize,
>(pub [AggregatorCircuitInputs<C>; B]);

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, const B: usize> Default
    for BatchedAggregatorCircuitInputs<C, B>
{
    fn default() -> Self {
        Self(array::from_fn(|_| AggregatorCircuitInputs::default()))
    }
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

#[derive(Clone, Debug)]
pub struct BatchedAggregatorCircuitInputsVar<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    CVar: CurveVar<C, C::BaseField>,
    const B: usize,
>(pub [AggregatorCircuitInputsVar<C, CVar>; B]);

impl<C: CurveGroup<BaseField: PrimeField + Absorb>, CVar: CurveVar<C, C::BaseField>>
    AllocVar<AggregatorCircuitInputs<C>, C::BaseField> for AggregatorCircuitInputsVar<C, CVar>
{
    fn new_variable<T: std::borrow::Borrow<AggregatorCircuitInputs<C>>>(
        cs: impl Into<Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let v = f()?;
        let AggregatorCircuitInputs {
            tx,
            tx_tree_update_proof,
            utxo_tree_deletion_proofs,
            utxo_tree_deletion_positions,
            utxo_tree_addition_proofs,
            utxo_tree_addition_positions,
            signer_tree_update_proof,
            sender_pk,
            signature,
        } = v.borrow();
        Ok(Self {
            tx: TransactionVar::new_variable(cs.clone(), || Ok(tx), mode)?,
            tx_tree_update_proof: MerkleSparseTreeTwoPathsVar::new_variable(
                cs.clone(),
                || Ok(tx_tree_update_proof),
                mode,
            )?,
            utxo_tree_deletion_proofs: Vec::new_variable(
                cs.clone(),
                || Ok(&utxo_tree_deletion_proofs[..]),
                mode,
            )?
            .try_into()
            .unwrap(),
            utxo_tree_deletion_positions: Vec::new_variable(
                cs.clone(),
                || Ok(&utxo_tree_deletion_positions[..]),
                mode,
            )?
            .try_into()
            .unwrap(),
            utxo_tree_addition_proofs: Vec::new_variable(
                cs.clone(),
                || Ok(&utxo_tree_addition_proofs[..]),
                mode,
            )?
            .try_into()
            .unwrap(),
            utxo_tree_addition_positions: Vec::new_variable(
                cs.clone(),
                || Ok(&utxo_tree_addition_positions[..]),
                mode,
            )?
            .try_into()
            .unwrap(),
            signer_tree_update_proof: MerkleSparseTreeTwoPathsVar::new_variable(
                cs.clone(),
                || Ok(signer_tree_update_proof),
                mode,
            )?,
            sender_pk: PublicKeyVar::new_variable(cs.clone(), || Ok(sender_pk), mode)?,
            signature: SignatureVar::new_variable(cs, || Ok(signature), mode)?,
        })
    }
}

impl<
        C: CurveGroup<BaseField: PrimeField + Absorb>,
        CVar: CurveVar<C, C::BaseField>,
        const B: usize,
    > AllocVar<BatchedAggregatorCircuitInputs<C, B>, C::BaseField>
    for BatchedAggregatorCircuitInputsVar<C, CVar, B>
{
    fn new_variable<T: std::borrow::Borrow<BatchedAggregatorCircuitInputs<C, B>>>(
        cs: impl Into<Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let v = f()?;
        let v = v.borrow();
        Ok(Self(
            <[AggregatorCircuitInputsVar<C, CVar>; B] as AllocVar<
                [AggregatorCircuitInputs<C>; B],
                _,
            >>::new_variable(cs, || Ok(&v.0), mode)?,
        ))
    }
}

impl<
        C: CurveGroup<BaseField: PrimeField + Absorb>,
        CVar: CurveVar<C, C::BaseField>,
        const B: usize,
    > AggregatorCircuit<C, CVar, B>
{
    pub fn tx_is_deposit(
        tx: &TransactionVar<C::BaseField, C, CVar>,
        contract_pk: &PublicKeyVar<C, CVar>,
    ) -> Result<Boolean<C::BaseField>, SynthesisError> {
        Boolean::kary_and(
            &tx.inputs
                .iter()
                .map(|utxo| Ok(&utxo.is_dummy | (utxo.pk.key.is_eq(&contract_pk.key)?)))
                .collect::<Result<Vec<_>, _>>()?,
        )
    }
}

impl<
        C: CurveGroup<BaseField: PrimeField + Absorb>,
        CVar: CurveVar<C, C::BaseField>,
        const B: usize,
    > FCircuit<C::BaseField> for AggregatorCircuit<C, CVar, B>
{
    type Params = (PoseidonConfig<C::BaseField>, PublicKey<C>, bool);

    type ExternalInputs = BatchedAggregatorCircuitInputs<C, B>;

    type ExternalInputsVar = BatchedAggregatorCircuitInputsVar<C, CVar, B>;

    fn new(
        (poseidon_config, contract_pk, transfer_only): Self::Params,
    ) -> Result<Self, folding_schemes::Error> {
        Ok(Self {
            _c: PhantomData,
            poseidon_config,
            contract_pk,
            transfer_only,
        })
    }

    fn state_len(&self) -> usize {
        8
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
        let pp = CRHParametersVar::new_constant(cs.clone(), &self.poseidon_config)?;
        let contract_pk = PublicKeyVar::<C, CVar>::new_constant(cs.clone(), self.contract_pk)?;

        let mut step = z_i[0].clone();
        let mut utxo_root = z_i[1].clone();
        let mut tx_root = z_i[2].clone();
        let tx_root_final = z_i[3].clone();
        let mut signer_root = z_i[4].clone();
        let mut signer_acc = z_i[5].clone();
        let mut deposit_acc = z_i[6].clone();
        let mut withdrawal_acc = z_i[7].clone();

        for inputs in external_inputs.0 {
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
            } = inputs;

            tx.enforce_valid(&sender_pk)?;

            let (tx_root_old, tx_root_new) = tx_tree_update_proof.update_root(
                &pp,
                &pp,
                &TransactionVar::new_constant(cs.clone(), Transaction::default())?,
                &tx,
                &step,
            )?;
            tx_root_old.enforce_equal(&tx_root)?;
            tx_root = tx_root_new;

            let signature_validity = sender_pk.is_signature_valid::<32>(
                &pp,
                &[
                    TryInto::<Vec<_>>::try_into(&tx)?,
                    vec![tx_root_final.clone()],
                ]
                .concat(),
                signature,
            )?;
            let sender_is_contract = sender_pk.key.is_eq(&contract_pk.key)?;
            let tx_validity = &signature_validity | &sender_is_contract;

            for i in 0..TX_IO_SIZE {
                let should_delete = &signature_validity & !&tx.inputs[i].is_dummy;

                let (utxo_root_old, utxo_root_new) = utxo_tree_deletion_proofs[i].update_root(
                    &pp,
                    &pp,
                    &tx.inputs[i],
                    &UTXOVar::new_constant(cs.clone(), UTXO::default())?,
                    &utxo_tree_deletion_positions[i],
                )?;
                utxo_root.conditional_enforce_equal(&utxo_root_old, &should_delete)?;
                utxo_root = should_delete.select(&utxo_root_new, &utxo_root)?;
            }

            let mut withdrawal_amount = FpVar::zero();
            for i in 0..TX_IO_SIZE {
                let receiver_is_contract = tx.outputs[i].pk.key.is_eq(&contract_pk.key)?;
                // Handle deposits
                if !self.transfer_only {
                    let mut deposit_preimage = vec![];
                    deposit_preimage.extend(deposit_acc.to_bytes_le()?);
                    deposit_preimage.extend(tx.outputs[i].pk.key.to_bytes_le()?);
                    let amount_bits = tx.outputs[i].amount.to_n_bits(64)?;
                    deposit_preimage.extend(
                        amount_bits
                            .chunks(8)
                            .map(UInt8::from_bits_le)
                            .collect::<Vec<_>>(),
                    );
                    deposit_acc = (&sender_is_contract & !&tx.outputs[i].is_dummy).select(
                        &Sha256Gadget::digest(&deposit_preimage)?.0[..31].to_constraint_field()?[0],
                        &deposit_acc,
                    )?;
                }
                withdrawal_amount += (&receiver_is_contract & !&tx.outputs[i].is_dummy)
                    .select(&tx.outputs[i].amount, &FpVar::zero())?;

                let should_add = &tx_validity & !receiver_is_contract & !&tx.outputs[i].is_dummy;
                let (utxo_root_old, utxo_root_new) = utxo_tree_addition_proofs[i].update_root(
                    &pp,
                    &pp,
                    &UTXOVar::new_constant(cs.clone(), UTXO::default())?,
                    &tx.outputs[i],
                    &utxo_tree_addition_positions[i],
                )?;
                utxo_root.conditional_enforce_equal(&utxo_root_old, &should_add)?;
                utxo_root = should_add.select(&utxo_root_new, &utxo_root)?;
            }

            let (signer_root_old, signer_root_new) = signer_tree_update_proof.update_root(
                &pp,
                &pp,
                &PublicKeyVar::new_constant(cs.clone(), PublicKey::default())?,
                &sender_pk,
                &step,
            )?;
            signer_root_old.conditional_enforce_equal(&signer_root, &tx_validity)?;
            signer_root = tx_validity.select(&signer_root_new, &signer_root)?;

            signer_acc = Sha256Gadget::digest(
                &[
                    signer_acc.to_bytes_le()?,
                    tx_validity
                        .select(&sender_pk.key, &CVar::zero())?
                        .to_bytes_le()?,
                ]
                .concat(),
            )?
            .0[..31]
                .to_constraint_field()?[0]
                .clone();

            if !self.transfer_only {
                let mut withdrawal_preimage = vec![];
                withdrawal_preimage.extend(withdrawal_acc.to_bytes_le()?);
                withdrawal_preimage.extend(sender_pk.key.to_bytes_le()?);
                withdrawal_preimage.extend(
                    withdrawal_amount
                        .to_n_bits(64)?
                        .chunks(8)
                        .map(UInt8::from_bits_le),
                );
                withdrawal_acc = withdrawal_amount.is_zero()?.select(
                    &withdrawal_acc,
                    &Sha256Gadget::digest(&withdrawal_preimage)?.0[..31].to_constraint_field()?[0],
                )?;
            }
            step += FpVar::one();
        }

        Ok(vec![
            step,
            utxo_root,
            tx_root,
            tx_root_final,
            signer_root,
            signer_acc,
            deposit_acc,
            withdrawal_acc,
        ])
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use crate::{
        tests::{advance_epoch, aggregator_setup},
        AggregatorState,
    };

    use super::*;
    use ark_bn254::{Fr, G1Projective as Projective};
    use ark_ff::UniformRand;
    use ark_grumpkin::{constraints::GVar, Projective as Projective2};
    use ark_relations::gr1cs::ConstraintSystem;
    use ark_serialize::CanonicalSerialize;
    use ark_std::rand::thread_rng;
    use folding_schemes::{
        arith::Arith,
        commitment::pedersen::Pedersen,
        folding::nova::{Nova, PreprocessorParam},
        transcript::poseidon::poseidon_canonical_config,
        FoldingScheme,
    };

    const B: usize = 1;

    #[test]
    fn test_num_constraints_transfer_only_mode() {
        let poseidon_config = poseidon_canonical_config();
        let contract_pk = PublicKey::<Projective2>::default();

        let cs = ConstraintSystem::new_ref();

        let circuit =
            AggregatorCircuit::<Projective2, GVar, B>::new((poseidon_config, contract_pk, true))
                .unwrap();

        let inputs = BatchedAggregatorCircuitInputs::<Projective2, B>::default();
        let inputs_var = BatchedAggregatorCircuitInputsVar::<Projective2, GVar, B>::new_witness(
            cs.clone(),
            || Ok(inputs),
        )
        .unwrap();

        circuit
            .generate_step_constraints(
                cs.clone(),
                0,
                vec![FpVar::zero(); circuit.state_len()],
                inputs_var,
            )
            .unwrap();

        println!("{}", cs.num_constraints());
    }

    #[test]
    fn test_num_constraints_full_mode() {
        let poseidon_config = poseidon_canonical_config();
        let contract_pk = PublicKey::<Projective2>::default();

        let cs = ConstraintSystem::new_ref();

        let circuit =
            AggregatorCircuit::<Projective2, GVar, B>::new((poseidon_config, contract_pk, false))
                .unwrap();

        let inputs = BatchedAggregatorCircuitInputs::<Projective2, B>::default();
        let inputs_var = BatchedAggregatorCircuitInputsVar::<Projective2, GVar, B>::new_witness(
            cs.clone(),
            || Ok(inputs),
        )
        .unwrap();

        circuit
            .generate_step_constraints(
                cs.clone(),
                0,
                vec![FpVar::zero(); circuit.state_len()],
                inputs_var,
            )
            .unwrap();

        println!("{}", cs.num_constraints());
    }

    #[test]
    fn test_aggregator_circuit_full_mode() {
        let rng = &mut thread_rng();
        let n_users = 5;
        let (config, mut contract_state, mut aggregator, users) = aggregator_setup(rng, n_users);
        let empty_utxo_root = aggregator.utxo_tree.root();
        let empty_tx_root = aggregator.transaction_tree.root();
        let empty_signer_root = aggregator.signer_tree.root();

        let rollup_pk = users[0].keypair.pk;

        let transactions = vec![
            Transaction {
                // Contract (80) + Contract (20) -> User 1 (100)
                inputs: [
                    UTXO::new(users[0].keypair.pk, 80),
                    UTXO::new(users[0].keypair.pk, 20),
                    UTXO::dummy(),
                    UTXO::dummy(),
                ],
                outputs: [
                    UTXO::new(users[1].keypair.pk, 100),
                    UTXO::dummy(),
                    UTXO::dummy(),
                    UTXO::dummy(),
                ],
            },
            Transaction {
                // User 1 (100) -> User 2 (30) + User 3 (40) + User 1 (30)
                inputs: [
                    UTXO::new(users[1].keypair.pk, 100),
                    UTXO::dummy(),
                    UTXO::dummy(),
                    UTXO::dummy(),
                ],
                outputs: [
                    UTXO::new(users[2].keypair.pk, 30),
                    UTXO::new(users[3].keypair.pk, 40),
                    UTXO::new(users[1].keypair.pk, 30),
                    UTXO::dummy(),
                ],
            },
            Transaction {
                // User 2 (30) -> User 3 (10) + User 4 (20)
                inputs: [
                    UTXO::new(users[2].keypair.pk, 30),
                    UTXO::dummy(),
                    UTXO::dummy(),
                    UTXO::dummy(),
                ],
                outputs: [
                    UTXO::new(users[3].keypair.pk, 10),
                    UTXO::new(users[4].keypair.pk, 20),
                    UTXO::dummy(),
                    UTXO::dummy(),
                ],
            },
            Transaction {
                // User 3 (40) + User 3 (10) -> User 4 (20) + User 3 (30)
                inputs: [
                    UTXO::new(users[3].keypair.pk, 40),
                    UTXO::new(users[3].keypair.pk, 10),
                    UTXO::dummy(),
                    UTXO::dummy(),
                ],
                outputs: [
                    UTXO::new(users[4].keypair.pk, 20),
                    UTXO::new(users[3].keypair.pk, 30),
                    UTXO::dummy(),
                    UTXO::dummy(),
                ],
            },
            Transaction {
                // User 4 (20) + User 4 (20) -> Contract (30) + Contract (10)
                inputs: [
                    UTXO::new(users[4].keypair.pk, 20),
                    UTXO::new(users[4].keypair.pk, 20),
                    UTXO::dummy(),
                    UTXO::dummy(),
                ],
                outputs: [
                    UTXO::new(users[0].keypair.pk, 30),
                    UTXO::new(users[0].keypair.pk, 10),
                    UTXO::dummy(),
                    UTXO::dummy(),
                ],
            },
        ];

        let block = advance_epoch(
            rng,
            &config,
            &mut aggregator,
            &users,
            &mut contract_state,
            &transactions,
        );

        let cs = ConstraintSystem::new_ref();

        let inputs = aggregator.ivc_inputs();
        let inputs_var = Vec::new_witness(cs.clone(), || Ok(inputs)).unwrap();

        let circuit =
            AggregatorCircuit::<Projective2, GVar, B>::new((config, rollup_pk, false)).unwrap();

        let mut z = vec![
            FpVar::zero(),
            FpVar::constant(empty_utxo_root),
            FpVar::constant(empty_tx_root),
            FpVar::new_witness(cs.clone(), || Ok(aggregator.transaction_tree.root())).unwrap(),
            FpVar::constant(empty_signer_root),
            FpVar::zero(),
            FpVar::zero(),
            FpVar::zero(),
        ];

        for (i, v) in inputs_var.into_iter().array_chunks::<B>().enumerate() {
            z = circuit
                .generate_step_constraints(cs.clone(), i, z, BatchedAggregatorCircuitInputsVar(v))
                .unwrap();
        }

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(
            z.value().unwrap(),
            contract_state.derive_public_inputs(block)
        );
    }

    #[bench]
    fn bench_aggregator_circuit_full_mode(b: &mut test::Bencher) {
        let mut rng = &mut thread_rng();
        let config = poseidon_canonical_config::<Fr>();
        let aggregator = AggregatorState::<Fr, Projective2>::new(config.clone());

        let empty_utxo_root = aggregator.utxo_tree.root();
        let empty_tx_root = aggregator.transaction_tree.root();
        let empty_signer_root = aggregator.signer_tree.root();

        let rollup_pk = PublicKey {
            key: Projective2::rand(rng),
        };

        let circuit =
            AggregatorCircuit::<Projective2, GVar, B>::new((config.clone(), rollup_pk, false))
                .unwrap();

        type N = Nova<
            Projective,
            Projective2,
            AggregatorCircuit<Projective2, GVar, B>,
            Pedersen<Projective>,
            Pedersen<Projective2>,
            false,
        >;

        let nova_preprocess_params = PreprocessorParam::new(config.clone(), circuit.clone());

        let nova_params = N::preprocess(&mut rng, &nova_preprocess_params).unwrap();

        // avoid taking preprocessing step into account
        let nova_params = nova_params.clone();

        let z = vec![
            Fr::zero(),
            empty_utxo_root,
            empty_tx_root,
            aggregator.transaction_tree.root(),
            empty_signer_root,
            Fr::zero(),
            Fr::zero(),
            Fr::zero(),
        ];
        let mut folding_scheme = N::init(&nova_params, circuit, z.clone()).unwrap();

        let inputs = BatchedAggregatorCircuitInputs::<_, B>::default();

        folding_scheme
            .prove_step(&mut rng, inputs.clone(), None)
            .unwrap();

        let pp_size = nova_params.0.compressed_size() + config.compressed_size();

        let vp_size = nova_params.1.compressed_size()
            + nova_params.1.r1cs.compressed_size()
            + nova_params.1.cf_r1cs.compressed_size();

        println!(
            "[All tx types] Batch size: {B}, total circuit size: {}, params size: {}",
            nova_params.1.r1cs.n_constraints(),
            pp_size + vp_size
        );

        let now = Instant::now();
        folding_scheme
            .prove_step(&mut rng, inputs.clone(), None)
            .unwrap();
        println!("{:?}", now.elapsed());

        b.iter(|| {
            folding_scheme
                .prove_step(&mut rng, inputs.clone(), None)
                .unwrap();
        });
    }

    #[bench]
    fn bench_aggregator_circuit_transfer_only_mode(b: &mut test::Bencher) {
        let mut rng = &mut thread_rng();
        let config = poseidon_canonical_config::<Fr>();
        let aggregator = AggregatorState::<Fr, Projective2>::new(config.clone());

        let empty_utxo_root = aggregator.utxo_tree.root();
        let empty_tx_root = aggregator.transaction_tree.root();
        let empty_signer_root = aggregator.signer_tree.root();

        let rollup_pk = PublicKey {
            key: Projective2::rand(rng),
        };

        let circuit =
            AggregatorCircuit::<Projective2, GVar, B>::new((config.clone(), rollup_pk, true))
                .unwrap();

        type N = Nova<
            Projective,
            Projective2,
            AggregatorCircuit<Projective2, GVar, B>,
            Pedersen<Projective>,
            Pedersen<Projective2>,
            false,
        >;

        let nova_preprocess_params = PreprocessorParam::new(config.clone(), circuit.clone());

        let nova_params = N::preprocess(&mut rng, &nova_preprocess_params).unwrap();

        let pp_size = nova_params.0.compressed_size() + config.compressed_size();

        let vp_size = nova_params.1.compressed_size()
            + nova_params.1.r1cs.compressed_size()
            + nova_params.1.cf_r1cs.compressed_size();

        println!(
            "[Transfer only] Batch size: {B}, total circuit size: {}, params size: {}",
            nova_params.1.r1cs.n_constraints(),
            pp_size + vp_size
        );

        let z = vec![
            Fr::zero(),
            empty_utxo_root,
            empty_tx_root,
            aggregator.transaction_tree.root(),
            empty_signer_root,
            Fr::zero(),
            Fr::zero(),
            Fr::zero(),
        ];
        let mut folding_scheme = N::init(&nova_params, circuit, z.clone()).unwrap();

        let inputs = BatchedAggregatorCircuitInputs::<_, B>::default();

        folding_scheme
            .prove_step(&mut rng, inputs.clone(), None)
            .unwrap();

        let now = Instant::now();
        folding_scheme
            .prove_step(&mut rng, inputs.clone(), None)
            .unwrap();
        println!("{:?}", now.elapsed());

        b.iter(|| {
            folding_scheme
                .prove_step(&mut rng, inputs.clone(), None)
                .unwrap();
        });
    }
}
