#![feature(test)]
#![feature(iter_array_chunks)]
extern crate test;

use std::{array::from_fn, collections::HashMap};

use ark_crypto_primitives::{
    sponge::{poseidon::PoseidonConfig, Absorb},
    Error,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use errors::AggregatorError;
use mock_contract::MockContract;
use plasma_fold::{
    datastructures::{
        block::Block,
        keypair::{PublicKey, Signature},
        signerlist::{SignerTree, SignerTreeConfig},
        transaction::{Transaction, TransactionTree, TransactionTreeConfig},
        utxo::{UTXOTree, UTXOTreeConfig, UTXO},
        TX_IO_SIZE,
    },
    errors::TransactionError,
    primitives::sparsemt::{MerkleSparseTreePath, MerkleSparseTreeTwoPaths},
};

use crate::circuit::AggregatorCircuitInputs;

pub mod circuit;
pub mod errors;

pub struct AggregatorState<F: PrimeField + Absorb, C: CurveGroup<BaseField = F>> {
    pub config: PoseidonConfig<F>,

    pub utxos: HashMap<UTXO<C>, Vec<usize>>,
    pub utxo_tree: UTXOTree<UTXOTreeConfig<C>>,
    pub current_utxo_index: usize,
    pub transactions: Vec<Transaction<C>>,
    pub transaction_tree: TransactionTree<TransactionTreeConfig<C>>,
    pub deposits: Vec<(PublicKey<C>, u64)>,
    pub withdrawals: Vec<(PublicKey<C>, u64)>,
    pub signer_tree: SignerTree<SignerTreeConfig<C>>,
    pub signers: Vec<Option<PublicKey<C>>>,
    pub height: usize,
    pub acc_signer: F,
    pub acc_pk: F,

    pub tx_tree_update_proofs: Vec<MerkleSparseTreeTwoPaths<TransactionTreeConfig<C>>>,
    pub ivc_inputs: Vec<AggregatorCircuitInputs<C>>,
}

impl<F: PrimeField + Absorb, C: CurveGroup<BaseField = F>> AggregatorState<F, C> {
    pub fn new(config: PoseidonConfig<F>) -> Self {
        Self {
            utxos: HashMap::new(),
            utxo_tree: UTXOTree::blank(&config, &config),
            current_utxo_index: 0,
            transactions: vec![],
            transaction_tree: TransactionTree::blank(&config, &config),
            signer_tree: SignerTree::blank(&config, &config),
            config,
            height: 0,
            deposits: vec![],
            withdrawals: vec![],
            signers: vec![],
            acc_signer: F::zero(),
            acc_pk: F::zero(),
            tx_tree_update_proofs: vec![],
            ivc_inputs: vec![],
        }
    }

    pub fn reset_for_new_epoch(&mut self) {
        self.transactions.clear();
        self.transaction_tree = TransactionTree::blank(&self.config, &self.config);
        self.deposits.clear();
        self.withdrawals.clear();
        self.signers.clear();
        self.acc_signer = F::zero();
        self.acc_pk = F::zero();
        self.tx_tree_update_proofs.clear();
        self.ivc_inputs.clear();
    }

    pub fn process_transactions(
        &mut self,
        inputs: Vec<(PublicKey<C>, Transaction<C>)>,
    ) -> Result<(), TransactionError> {
        for (sender, tx) in inputs {
            tx.is_valid(Some(sender))?;
            self.tx_tree_update_proofs.push(
                self.transaction_tree
                    .update_and_prove(self.transactions.len() as u64, &tx)
                    .map_err(|_| TransactionError::TransactionTreeFailure)?,
            );
            self.transactions.push(tx);
        }

        Ok(())
    }

    pub fn prove_transactions(
        &self,
    ) -> Result<Vec<MerkleSparseTreePath<TransactionTreeConfig<C>>>, Error> {
        self.transactions
            .iter()
            .enumerate()
            .map(|(i, tx)| self.transaction_tree.generate_proof(i as u64, tx))
            .collect::<Result<Vec<_>, _>>()
    }

    pub fn process_signatures(
        &mut self,
        rollup_contract_pk: PublicKey<C>,
        inputs: Vec<(PublicKey<C>, Option<Signature<C::ScalarField>>)>,
    ) -> Result<(), AggregatorError> {
        for (i, (pk, sig)) in inputs.into_iter().enumerate() {
            let tx = &self.transactions[i];

            let signer_tree_update_proof;
            let mut utxo_tree_addition_positions = [C::BaseField::zero(); TX_IO_SIZE];
            let mut utxo_tree_deletion_positions = [C::BaseField::zero(); TX_IO_SIZE];
            let mut utxo_tree_addition_proofs: [MerkleSparseTreeTwoPaths<_>; TX_IO_SIZE] =
                from_fn(|_| MerkleSparseTreeTwoPaths::default());
            let mut utxo_tree_deletion_proofs: [MerkleSparseTreeTwoPaths<_>; TX_IO_SIZE] =
                from_fn(|_| MerkleSparseTreeTwoPaths::default());
            let sig = sig.unwrap_or_default();

            if pk
                .verify_signature(
                    &self.config,
                    &[Into::<Vec<_>>::into(tx), vec![self.transaction_tree.root()]].concat(),
                    &sig,
                )
                .map_err(|_| AggregatorError::SignatureError)?
                || pk == rollup_contract_pk
            {
                signer_tree_update_proof = self
                    .signer_tree
                    .update_and_prove(self.signers.len() as u64, &pk)
                    .map_err(|_| AggregatorError::UTXOTreeUpdateError)?;
                self.signers.push(Some(pk));
                for (j, &utxo) in tx
                    .inputs
                    .iter()
                    .enumerate()
                    .filter(|(_, utxo)| !utxo.is_dummy)
                {
                    if utxo.pk != rollup_contract_pk {
                        // if the sending pk does not belong to the contract, check that the utxo
                        // exists
                        if !self.utxos.contains_key(&utxo) {
                            return Err(AggregatorError::UTXONonExisting);
                        };

                        let index = self
                            .utxos
                            .get_mut(&utxo)
                            .unwrap()
                            .pop()
                            .ok_or(AggregatorError::UTXOError)?;

                        utxo_tree_deletion_positions[j] = C::BaseField::from(index as u64);
                        utxo_tree_deletion_proofs[j] = self
                            .utxo_tree
                            .update_and_prove(index as u64, &UTXO::dummy())
                            .map_err(|_| AggregatorError::UTXOTreeUpdateError)?;
                    }
                }
                let mut withdrawal_amount = 0;
                for (j, &utxo) in tx
                    .outputs
                    .iter()
                    .enumerate()
                    .filter(|(_, utxo)| !utxo.is_dummy)
                {
                    if pk == rollup_contract_pk {
                        // when the sender is the rollup, then the output UTXO is a deposit
                        self.deposits.push((utxo.pk, utxo.amount));
                    }
                    if utxo.pk != rollup_contract_pk {
                        // this output utxo is for a regular user
                        // update the utxo tree with it
                        self.utxos
                            .entry(utxo)
                            .or_default()
                            .push(self.current_utxo_index);

                        utxo_tree_addition_positions[j] =
                            C::BaseField::from(self.current_utxo_index as u64);
                        utxo_tree_addition_proofs[j] = self
                            .utxo_tree
                            .update_and_prove(self.current_utxo_index as u64, &utxo)
                            .map_err(|_| AggregatorError::UTXOTreeUpdateError)?;
                        self.current_utxo_index += 1;
                    } else {
                        withdrawal_amount += utxo.amount;
                    }
                }
                if withdrawal_amount > 0 {
                    self.withdrawals.push((pk, withdrawal_amount));
                }
            } else {
                signer_tree_update_proof = MerkleSparseTreeTwoPaths::default();
                // the signature has not been verified or is not existent. we push \bot to the list
                // of signers
                self.signers.push(None);
            }

            self.ivc_inputs.push(AggregatorCircuitInputs {
                tx: tx.clone(),
                tx_tree_update_proof: self.tx_tree_update_proofs[i].clone(),
                utxo_tree_addition_positions,
                utxo_tree_deletion_positions,
                utxo_tree_addition_proofs,
                utxo_tree_deletion_proofs,
                signer_tree_update_proof,
                sender_pk: pk,
                signature: sig,
            })
        }

        Ok(())
    }

    pub fn produce_block(&self, onchain_state: &MockContract<C>) -> Block<F> {
        Block {
            utxo_tree_root: self.utxo_tree.root(),
            tx_tree_root: self.transaction_tree.root(),
            signer_tree_root: self.signer_tree.root(),
            signers: self
                .signers
                .iter()
                .map(|s| s.as_ref().map(|pk| onchain_state.pk_indices[pk] as u32))
                .collect(),
            height: self.height,
            deposits: self
                .deposits
                .iter()
                .map(|(pk, amount)| (onchain_state.pk_indices[pk] as u32, *amount))
                .collect(),
            withdrawals: self
                .withdrawals
                .iter()
                .map(|(pk, amount)| (onchain_state.pk_indices[pk] as u32, *amount))
                .collect(),
        }
    }

    pub fn ivc_inputs(&self) -> Vec<AggregatorCircuitInputs<C>> {
        self.ivc_inputs.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::G1Projective;
    use ark_std::rand::{thread_rng, Rng};
    use folding_schemes::transcript::poseidon::poseidon_canonical_config;
    use mock_contract::L1Account;
    use plasma_fold::datastructures::noncemap::Nonce;
    use plasma_fold::datastructures::{
        keypair::{KeyPair, SecretKey},
        user::User,
    };

    /// NOTE: vector of users should have the same order as the vector of transactions. i.e.
    /// users[i] has done transactions[i]. it also supposes that they have the same length.
    /// TODO: make this test a bit less mouthful?
    pub fn advance_epoch<C: CurveGroup<BaseField: PrimeField + Absorb>>(
        rng: &mut impl Rng,
        config: &PoseidonConfig<C::BaseField>,
        aggregator: &mut AggregatorState<C::BaseField, C>,
        users: &Vec<User<C>>,
        onchain_state: &MockContract<C>,
        transactions: &Vec<Transaction<C>>,
    ) -> Block<C::BaseField> {
        let rollup_pk = onchain_state.pks[0];

        aggregator
            .process_transactions(
                transactions
                    .into_iter()
                    .zip(users)
                    .map(|(tx, user)| (user.keypair.pk, tx.clone()))
                    .collect(),
            )
            .unwrap();

        let paths = aggregator.prove_transactions().unwrap();

        let inputs = paths
            .iter()
            .enumerate()
            .map(|(i, path)| {
                // user verifies path
                let tx = &transactions[i];

                let tx_in_tx_tree = path.verify_with_index(
                    &config,
                    &config,
                    &aggregator.transaction_tree.root(),
                    tx,
                    i as u64,
                );

                assert!(tx_in_tx_tree.is_ok());

                let sk = &users[i].keypair.sk;
                let pk = users[i].keypair.pk;
                let sig = if pk == rollup_pk {
                    None
                } else {
                    // user signs the transaction
                    Some(
                        sk.sign::<C>(
                            &config,
                            &[
                                Into::<Vec<_>>::into(&transactions[i]),
                                vec![aggregator.transaction_tree.root()],
                            ]
                            .concat(),
                            rng,
                        )
                        .unwrap(),
                    )
                };
                (pk, sig)
            })
            .collect();

        aggregator.process_signatures(rollup_pk, inputs).unwrap();

        aggregator.produce_block(onchain_state)
    }

    pub fn aggregator_setup<C: CurveGroup<BaseField: PrimeField + Absorb>>(
        rng: &mut impl Rng,
        n_users: usize,
    ) -> (
        PoseidonConfig<C::BaseField>,
        MockContract<C>,
        AggregatorState<C::BaseField, C>,
        Vec<User<C>>,
    ) {
        let sks = (0..n_users)
            .map(|_| SecretKey::<C::ScalarField>::new(rng))
            .collect::<Vec<_>>();

        let keypairs = sks
            .into_iter()
            .map(|sk| KeyPair {
                pk: PublicKey::<C>::new(&sk),
                sk,
            })
            .collect::<Vec<_>>();

        let mut contract_state = MockContract::<C>::new(keypairs[0].pk);

        let mut l1_users = vec![L1Account::new(0); n_users];

        let mut l2_users = keypairs
            .into_iter()
            .enumerate()
            .map(|(i, kp)| User {
                keypair: kp,
                balance: 0,
                nonce: Nonce(0),
                acc: C::ScalarField::default(),
                id: (i as u32) + 1, // 0 is reserved for aggregator
            })
            .collect::<Vec<User<C>>>();

        l2_users[0].balance = u64::MAX; // Contract starts with max L2 balance
        l1_users[1].balance = 100; // User 1 starts with 100 L1 balance

        for i in 1..n_users {
            contract_state.join(l1_users[i], l2_users[i].keypair.pk);
        }

        let config = poseidon_canonical_config::<C::BaseField>();
        let aggregator = AggregatorState::new(config.clone());

        (config, contract_state, aggregator, l2_users)
    }

    #[test]
    fn test_aggregator_native_valid() {
        let mut rng = &mut thread_rng();
        let n_users = 5;
        let (config, mut contract_state, mut aggregator, users) =
            aggregator_setup::<G1Projective>(rng, n_users);

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

        advance_epoch(
            &mut rng,
            &config,
            &mut aggregator,
            &users,
            &mut contract_state,
            &transactions,
        );

        // reset aggregator and make another batch of transactions
        aggregator.reset_for_new_epoch();
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

        advance_epoch(
            &mut rng,
            &config,
            &mut aggregator,
            &users,
            &mut contract_state,
            &transactions,
        );
    }

    #[should_panic]
    #[test]
    fn test_aggregator_native_invalid_utxo() {
        // testing whether providing an invalid utxo makes the aggregator fail
        let mut rng = &mut thread_rng();
        let n_users = 4; // includes aggregator
        let (config, mut contract_state, mut aggregator, users) =
            aggregator_setup::<G1Projective>(rng, n_users);

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
                    // NOTE: Incorrect utxo, UTXONonExisting
                    UTXO::new(users[1].keypair.pk, 110),
                    UTXO::dummy(),
                    UTXO::dummy(),
                    UTXO::dummy(),
                ],
                outputs: [
                    UTXO::new(users[2].keypair.pk, 30),
                    UTXO::new(users[3].keypair.pk, 40),
                    UTXO::new(users[1].keypair.pk, 40),
                    UTXO::dummy(),
                ],
            },
            Transaction {
                // User 2 (30) -> User 3 (10)
                inputs: [
                    UTXO::new(users[2].keypair.pk, 30),
                    UTXO::dummy(),
                    UTXO::dummy(),
                    UTXO::dummy(),
                ],
                outputs: [
                    UTXO::new(users[3].keypair.pk, 10),
                    UTXO::new(users[3].keypair.pk, 20),
                    UTXO::dummy(),
                    UTXO::dummy(),
                ],
            },
        ];

        advance_epoch(
            &mut rng,
            &config,
            &mut aggregator,
            &users,
            &mut contract_state,
            &transactions,
        );
    }

    #[should_panic]
    #[test]
    fn test_aggregator_native_invalid_sum() {
        // testing whether providing an invalid utxo makes the aggregator fail
        let mut rng = &mut thread_rng();
        let n_users = 4;
        let (config, mut contract_state, mut aggregator, users) =
            aggregator_setup::<G1Projective>(rng, n_users);

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
                    // NOTE: Incorrect utxo amounts, InvalidAmounts
                    UTXO::new(users[1].keypair.pk, 100),
                    UTXO::dummy(),
                    UTXO::dummy(),
                    UTXO::dummy(),
                ],
                outputs: [
                    UTXO::new(users[2].keypair.pk, 30),
                    UTXO::new(users[3].keypair.pk, 10),
                    UTXO::new(users[1].keypair.pk, 10),
                    UTXO::dummy(),
                ],
            },
            Transaction {
                // User 2 (30) -> User 3 (10)
                inputs: [
                    UTXO::new(users[2].keypair.pk, 30),
                    UTXO::dummy(),
                    UTXO::dummy(),
                    UTXO::dummy(),
                ],
                outputs: [
                    UTXO::new(users[3].keypair.pk, 10),
                    UTXO::new(users[3].keypair.pk, 20),
                    UTXO::dummy(),
                    UTXO::dummy(),
                ],
            },
        ];

        advance_epoch(
            &mut rng,
            &config,
            &mut aggregator,
            &users,
            &mut contract_state,
            &transactions,
        );
    }
}
