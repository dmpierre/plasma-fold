use std::collections::{BTreeMap, HashMap};

use ark_crypto_primitives::{
    crh::CRHScheme,
    sponge::{poseidon::PoseidonConfig, Absorb},
    Error,
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use errors::AggregatorError;
use plasma_fold::{
    datastructures::{
        block::Block,
        keypair::{PublicKey, Signature},
        noncemap::{Nonce, NonceTree, NonceTreeConfig},
        signerlist::{SignerTree, SignerTreeConfig},
        transaction::{Transaction, TransactionTree, TransactionTreeConfig},
        user::{UserId, ROLLUP_CONTRACT_ID},
        utxo::{UTXOTree, UTXOTreeConfig, UTXO},
    },
    errors::TransactionError,
    primitives::{crh::TransactionCRH, sparsemt::MerkleSparseTreePath},
};

pub mod circuit;
pub mod errors;

pub struct AggregatorState<F: PrimeField + Absorb, C: CurveGroup<BaseField = F>> {
    pub config: PoseidonConfig<F>,

    pub utxos: HashMap<UTXO<C>, Vec<usize>>,
    pub utxo_tree: UTXOTree<UTXOTreeConfig<C>>,
    pub current_utxo_index: usize,
    pub transactions: Vec<Transaction<C>>,
    pub transaction_tree: TransactionTree<TransactionTreeConfig<C>>,
    pub nonces: HashMap<C, Nonce>,
    pub nonce_tree: NonceTree<NonceTreeConfig<F>>,
    pub deposits: Vec<UTXO<C>>,
    pub withdrawals: Vec<UTXO<C>>,
    pub signer_tree: SignerTree<SignerTreeConfig<C>>,
    pub signers: Vec<Option<UserId>>,
    pub block_number: F,
    pub acc_signer: F,
    pub acc_pk: F,
}

impl<F: PrimeField + Absorb, C: CurveGroup<BaseField = F>> AggregatorState<F, C> {
    pub fn new(config: PoseidonConfig<F>) -> Self {
        Self {
            utxos: HashMap::new(),
            utxo_tree: UTXOTree::blank(&config, &config),
            current_utxo_index: 0,
            transactions: vec![],
            transaction_tree: TransactionTree::blank(&config, &config),
            nonces: HashMap::new(),
            nonce_tree: NonceTree::blank(&config, &config),
            signer_tree: SignerTree::blank(&config, &config),
            config,
            block_number: F::zero(),
            deposits: vec![],
            withdrawals: vec![],
            signers: vec![],
            acc_signer: F::zero(),
            acc_pk: F::zero(),
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
    }

    pub fn process_transactions(
        &mut self,
        inputs: Vec<(PublicKey<C>, Transaction<C>)>,
    ) -> Result<(), TransactionError> {
        for (sender, tx) in inputs {
            let nonce = self.nonces.entry(sender.key).or_insert(Nonce(0));
            tx.is_valid(Some(sender), Some(*nonce))?;
            self.transactions.push(tx);
            nonce.0 += 1;
        }
        self.transaction_tree = TransactionTree::new(
            &self.config,
            &self.config,
            &BTreeMap::from_iter(
                self.transactions
                    .iter()
                    .enumerate()
                    .map(|(i, tx)| (i as u64, tx.clone())),
            ),
        )
        .map_err(|_| TransactionError::TransactionTreeFailure)?;

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
        inputs: Vec<(UserId, PublicKey<C>, Option<Signature<C::ScalarField>>)>,
    ) -> Result<(), AggregatorError> {
        for (i, (sender, pk, sig)) in inputs.into_iter().enumerate() {
            let tx = &self.transactions[i];

            let hash = TransactionCRH::evaluate(&self.config, tx)
                .map_err(|_| AggregatorError::TransactionCRHError)?;

            if pk
                .verify_signature(&self.config, hash, &sig.unwrap_or_default())
                .map_err(|_| AggregatorError::SignatureError)?
                || sender == ROLLUP_CONTRACT_ID
            {
                self.signers.push(Some(sender));
                for &utxo in tx.inputs.iter().filter(|utxo| !utxo.is_dummy) {
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

                        self.utxo_tree
                            .update_and_prove(index as u64, &UTXO::dummy())
                            .map_err(|_| AggregatorError::UTXOTreeUpdateError)?;
                    }
                }
                for &utxo in tx.outputs.iter().filter(|utxo| !utxo.is_dummy) {
                    if sender == ROLLUP_CONTRACT_ID {
                        // when the sender is the rollup, then the output UTXO is a deposit
                        self.deposits.push(utxo);
                    }
                    if utxo.pk != rollup_contract_pk {
                        // this output utxo is for a regular user
                        // update the utxo tree with it
                        self.utxos
                            .entry(utxo)
                            .or_default()
                            .push(self.current_utxo_index);
                        self.utxo_tree
                            .update_and_prove(self.current_utxo_index as u64, &utxo)
                            .map_err(|_| AggregatorError::UTXOTreeUpdateError)?;
                        self.current_utxo_index += 1;
                    } else {
                        // the output utxo pk is the rollup, this is a withdrawal
                        self.withdrawals.push(UTXO {
                            amount: utxo.amount,
                            pk: utxo.pk,
                            is_dummy: false,
                        });
                    }
                }
            } else {
                // the signature has not been verified or is not existent. we push \bot to the list
                // of signers
                self.signers.push(None);
            }
        }

        Ok(())
    }

    pub fn produce_block(&self) -> Block<F> {
        Block {
            utxo_tree_root: self.utxo_tree.root(),
            tx_tree_root: self.transaction_tree.root(),
            signer_tree_root: self.signer_tree.root(),
            signers: self.signers.clone(),
            number: self.block_number.clone(), // deposits: self.deposits.clone(),
                                               // withdrawals: self.withdrawals.clone(),
        }
    }

    pub fn to_ivc_inputs(&self) {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fq, Fr, G1Projective};
    use ark_std::rand::{thread_rng, Rng};
    use folding_schemes::transcript::poseidon::poseidon_canonical_config;
    use plasma_fold::datastructures::{
        keypair::{KeyPair, SecretKey},
        user::User,
    };

    /// NOTE: vector of users should have the same order as the vector of transactions. i.e.
    /// users[i] has done transactions[i]. it also supposes that they have the same length.
    /// TODO: make this test a bit less mouthful?
    fn test_aggregator_native(
        rng: &mut impl Rng,
        config: &PoseidonConfig<Fq>,
        aggregator: &mut AggregatorState<Fq, G1Projective>,
        users: &Vec<User<G1Projective>>,
        rollup_pk: &PublicKey<G1Projective>,
        transactions: &Vec<Transaction<G1Projective>>,
    ) {
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

                let sender = users[i].id;
                let sk = &users[i].keypair.sk;
                let pk = users[i].keypair.pk;
                let sig = if sender == ROLLUP_CONTRACT_ID {
                    None
                } else {
                    // user signs the transaction
                    Some(
                        sk.sign::<G1Projective>(
                            &config,
                            TransactionCRH::evaluate(&config, transactions[i].clone()).unwrap(),
                            rng,
                        )
                        .unwrap(),
                    )
                };
                (sender, pk, sig)
            })
            .collect();

        aggregator
            .process_signatures(rollup_pk.clone(), inputs)
            .unwrap();

        let _ = aggregator.produce_block();

        aggregator.reset_for_new_epoch();
    }

    fn setup(
        rng: &mut impl Rng,
        n_users: usize,
    ) -> (
        PoseidonConfig<Fq>,
        AggregatorState<Fq, G1Projective>,
        Vec<User<G1Projective>>,
    ) {
        let rollup_sk = SecretKey::<Fr>::new(rng);
        let rollup_pk = PublicKey::<G1Projective>::new(&rollup_sk);
        let rollup_keypair = KeyPair {
            sk: rollup_sk,
            pk: rollup_pk,
        };

        let aggregator_as_user = User {
            keypair: rollup_keypair,
            balance: 0,
            nonce: Nonce(0),
            acc: Fr::default(),
            id: 0,
        };

        let sks = (1..n_users)
            .map(|_| SecretKey::<Fr>::new(rng))
            .collect::<Vec<_>>();

        let keypairs = sks
            .into_iter()
            .map(|sk| KeyPair {
                pk: PublicKey::<G1Projective>::new(&sk),
                sk,
            })
            .collect::<Vec<_>>();

        let mut users = keypairs
            .into_iter()
            .enumerate()
            .map(|(i, kp)| User {
                keypair: kp,
                balance: 0,
                nonce: Nonce(0),
                acc: Fr::default(),
                id: (i as u32) + 1, // 0 is reserved for aggregator
            })
            .collect::<Vec<User<G1Projective>>>();

        users.insert(0, aggregator_as_user);

        let config = poseidon_canonical_config::<Fq>();
        let aggregator = AggregatorState::new(config.clone());

        (config, aggregator, users)
    }

    #[test]
    fn test_aggregator_native_valid() {
        let mut rng = &mut thread_rng();
        let n_users = 5; // includes aggregator
        let (config, mut aggregator, users) = setup(rng, n_users);
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
                nonce: Nonce(0),
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
                nonce: Nonce(0),
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
                nonce: Nonce(0),
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
                nonce: Nonce(0),
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
                nonce: Nonce(0),
            },
        ];

        test_aggregator_native(
            &mut rng,
            &config,
            &mut aggregator,
            &users,
            &rollup_pk,
            &transactions,
        );

        aggregator.reset_for_new_epoch();

        // reset aggregator and make another batch of transactions
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
                nonce: Nonce(1),
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
                nonce: Nonce(1),
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
                nonce: Nonce(1),
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
                nonce: Nonce(1),
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
                nonce: Nonce(1),
            },
        ];

        test_aggregator_native(
            &mut rng,
            &config,
            &mut aggregator,
            &users,
            &rollup_pk,
            &transactions,
        );
    }

    #[should_panic]
    #[test]
    fn test_aggregator_native_invalid_nonce() {
        // testing whether providing an invalid nonce makes the aggregator fail
        let mut rng = &mut thread_rng();
        let n_users = 4; // includes aggregator
        let (config, mut aggregator, users) = setup(rng, n_users);
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
                nonce: Nonce(0),
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
                // NOTE: Incorrect nonce, InvalidNonce
                nonce: Nonce(42),
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
                nonce: Nonce(0),
            },
        ];

        test_aggregator_native(
            &mut rng,
            &config,
            &mut aggregator,
            &users,
            &rollup_pk,
            &transactions,
        );
    }

    #[should_panic]
    #[test]
    fn test_aggregator_native_invalid_utxo() {
        // testing whether providing an invalid utxo makes the aggregator fail
        let mut rng = &mut thread_rng();
        let n_users = 4; // includes aggregator
        let (config, mut aggregator, users) = setup(rng, n_users);
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
                nonce: Nonce(0),
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
                nonce: Nonce(0),
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
                nonce: Nonce(0),
            },
        ];

        test_aggregator_native(
            &mut rng,
            &config,
            &mut aggregator,
            &users,
            &rollup_pk,
            &transactions,
        );
    }

    #[should_panic]
    #[test]
    fn test_aggregator_native_invalid_sum() {
        // testing whether providing an invalid utxo makes the aggregator fail
        let mut rng = &mut thread_rng();
        let n_users = 4;
        let (config, mut aggregator, users) = setup(rng, n_users);
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
                nonce: Nonce(0),
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
                nonce: Nonce(0),
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
                nonce: Nonce(0),
            },
        ];

        test_aggregator_native(
            &mut rng,
            &config,
            &mut aggregator,
            &users,
            &rollup_pk,
            &transactions,
        );
    }
}
