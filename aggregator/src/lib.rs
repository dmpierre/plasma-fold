use std::collections::{BTreeMap, HashMap};

use ark_crypto_primitives::{
    crh::CRHScheme,
    merkle_tree::Path,
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use plasma_fold::{
    datastructures::{
        block::Block,
        keypair::{PublicKey, Signature},
        noncemap::{Nonce, NonceTree, NonceTreeConfig},
        transaction::{Transaction, TransactionTree, TransactionTreeConfig},
        user::{UserId, ROLLUP_CONTRACT_ID},
        utxo::{UTXOTree, UTXOTreeConfig, UTXO},
    },
    primitives::{crh::TransactionCRH, sparsemt::MerkleSparseTreePath},
};

pub mod circuit;

pub struct AggregatorState<F: PrimeField + Absorb> {
    pub config: PoseidonConfig<F>,

    pub utxos: HashMap<UTXO, Vec<usize>>,
    pub utxo_tree: UTXOTree<UTXOTreeConfig<F>>,
    pub current_utxo_index: usize,
    pub transactions: Vec<Transaction>,
    pub transaction_tree: TransactionTree<TransactionTreeConfig<F>>,
    pub nonces: HashMap<UserId, Nonce>,
    pub nonce_tree: NonceTree<NonceTreeConfig<F>>,
    pub deposits: Vec<UTXO>,
    pub withdrawals: Vec<UTXO>,
    pub signers: Vec<Option<UserId>>,

    pub acc_signer: F,
    pub acc_pk: F,
}

impl<F: PrimeField + Absorb> AggregatorState<F> {
    pub fn new(config: PoseidonConfig<F>) -> Self {
        Self {
            utxos: HashMap::new(),
            utxo_tree: UTXOTree::blank(&config, &config),
            current_utxo_index: 0,
            transactions: vec![],
            transaction_tree: TransactionTree::blank(&config, &config),
            nonces: HashMap::new(),
            nonce_tree: NonceTree::blank(&config, &config),
            config,
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

    pub fn process_transactions(&mut self, inputs: Vec<(UserId, Transaction)>) {
        for (sender, tx) in inputs {
            let nonce = self.nonces.entry(sender).or_insert(Nonce(0));
            if tx.is_valid(Some(sender), Some(*nonce)) {
                self.transactions.push(tx);
                nonce.0 += 1;
            }
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
        .unwrap();
    }

    pub fn prove_transactions(&self) -> Vec<MerkleSparseTreePath<TransactionTreeConfig<F>>> {
        self.transactions
            .iter()
            .enumerate()
            .map(|(i, tx)| self.transaction_tree.generate_proof(i as u64, tx))
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    pub fn process_signatures<C: CurveGroup<BaseField = F>>(
        &mut self,
        inputs: Vec<(UserId, PublicKey<C>, Option<Signature<C::ScalarField>>)>,
    ) {
        for (i, (sender, pk, sig)) in inputs.into_iter().enumerate() {
            let tx = &self.transactions[i];
            let hash = TransactionCRH::evaluate(&self.config, tx).unwrap();
            if pk
                .verify_signature(&self.config, hash, &sig.unwrap_or_default())
                .unwrap()
                || sender == ROLLUP_CONTRACT_ID
            {
                self.signers.push(Some(sender));
                for &utxo in tx.inputs.iter().filter(|utxo| !utxo.is_dummy) {
                    if utxo.id != ROLLUP_CONTRACT_ID {
                        assert!(self.utxos.contains_key(&utxo));
                        let index = self.utxos.get_mut(&utxo).unwrap().pop().unwrap();
                        self.utxo_tree
                            .update_and_prove(index as u64, &UTXO::dummy())
                            .unwrap();
                    }
                }
                for &utxo in tx.outputs.iter().filter(|utxo| !utxo.is_dummy) {
                    if sender == ROLLUP_CONTRACT_ID {
                        self.deposits.push(utxo);
                    }
                    if utxo.id != ROLLUP_CONTRACT_ID {
                        self.utxos
                            .entry(utxo)
                            .or_default()
                            .push(self.current_utxo_index);
                        self.utxo_tree
                            .update_and_prove(self.current_utxo_index as u64, &utxo)
                            .unwrap();
                        self.current_utxo_index += 1;
                    } else {
                        self.withdrawals.push(UTXO {
                            amount: utxo.amount,
                            id: sender,
                            is_dummy: false,
                        });
                    }
                }
            } else {
                self.signers.push(None);
            }
        }
    }

    pub fn produce_block(&self) -> Block<F> {
        Block {
            utxo_tree_root: self.utxo_tree.root(),
            tx_tree_root: self.transaction_tree.root(),
            signers: self.signers.clone(),
            deposits: self.deposits.clone(),
            withdrawals: self.withdrawals.clone(),
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
    use ark_std::rand::thread_rng;
    use folding_schemes::transcript::poseidon::poseidon_canonical_config;
    use plasma_fold::datastructures::keypair::SecretKey;

    fn test_aggregator_native(transactions_1: Vec<Transaction>, transactions_2: Vec<Transaction>) {
        let rng = &mut thread_rng();
        let config = poseidon_canonical_config::<Fq>();
        let mut aggregator = AggregatorState::new(config.clone());

        let sks = (0..5)
            .map(|_| SecretKey::<Fr>::new(rng))
            .collect::<Vec<_>>();
        let pks = sks
            .iter()
            .map(PublicKey::<G1Projective>::new)
            .collect::<Vec<_>>();
        let transactions = transactions_1;

        aggregator.process_transactions(
            transactions
                .iter()
                .map(|&tx| (tx.inputs[0].id, tx))
                .collect(),
        );

        let paths = aggregator.prove_transactions();

        aggregator.process_signatures(
            paths
                .iter()
                .enumerate()
                .map(|(i, path)| {
                    assert!(path
                        .verify_with_index(
                            &config,
                            &config,
                            &aggregator.transaction_tree.root(),
                            &transactions[i],
                            i as u64
                        )
                        .unwrap());
                    let sender = transactions[i].inputs[0].id;
                    let sk = &sks[sender as usize];
                    let pk = pks[sender as usize].clone();
                    let sig = if sender == ROLLUP_CONTRACT_ID {
                        None
                    } else {
                        Some(
                            sk.sign::<G1Projective>(
                                &config,
                                TransactionCRH::evaluate(&config, transactions[i]).unwrap(),
                                rng,
                            )
                            .unwrap(),
                        )
                    };
                    (sender, pk, sig)
                })
                .collect(),
        );

        let _ = aggregator.produce_block();

        aggregator.reset_for_new_epoch();

        let transactions = transactions_2;

        aggregator.process_transactions(
            transactions
                .iter()
                .map(|&tx| (tx.inputs[0].id, tx))
                .collect(),
        );

        assert_eq!(transactions, aggregator.transactions);

        let paths = aggregator.prove_transactions();

        aggregator.process_signatures(
            paths
                .iter()
                .enumerate()
                .map(|(i, path)| {
                    assert!(path
                        .verify_with_index(
                            &config,
                            &config,
                            &aggregator.transaction_tree.root(),
                            &transactions[i],
                            i as u64
                        )
                        .unwrap());
                    let sender = transactions[i].inputs[0].id;
                    let sk = &sks[sender as usize];
                    let pk = pks[sender as usize].clone();
                    let sig = if sender == ROLLUP_CONTRACT_ID {
                        None
                    } else {
                        Some(
                            sk.sign::<G1Projective>(
                                &config,
                                TransactionCRH::evaluate(&config, transactions[i]).unwrap(),
                                rng,
                            )
                            .unwrap(),
                        )
                    };
                    (sender, pk, sig)
                })
                .collect(),
        );
    }

    #[test]
    fn test_aggregator_native_valid() {
        test_aggregator_native(
            vec![
                Transaction {
                    // Contract (80) + Contract (20) -> User 1 (100)
                    inputs: [
                        UTXO::new(0, 80),
                        UTXO::new(0, 20),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    outputs: [
                        UTXO::new(1, 100),
                        UTXO::dummy(),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    nonce: Nonce(0),
                },
                Transaction {
                    // User 1 (100) -> User 2 (30) + User 3 (40) + User 1 (30)
                    inputs: [
                        UTXO::new(1, 100),
                        UTXO::dummy(),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    outputs: [
                        UTXO::new(2, 30),
                        UTXO::new(3, 40),
                        UTXO::new(1, 30),
                        UTXO::dummy(),
                    ],
                    nonce: Nonce(0),
                },
                Transaction {
                    // User 2 (30) -> User 3 (10) + User 4 (20)
                    inputs: [
                        UTXO::new(2, 30),
                        UTXO::dummy(),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    outputs: [
                        UTXO::new(3, 10),
                        UTXO::new(4, 20),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    nonce: Nonce(0),
                },
                Transaction {
                    // User 3 (40) + User 3 (10) -> User 4 (20) + User 3 (30)
                    inputs: [
                        UTXO::new(3, 40),
                        UTXO::new(3, 10),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    outputs: [
                        UTXO::new(4, 20),
                        UTXO::new(3, 30),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    nonce: Nonce(0),
                },
                Transaction {
                    // User 4 (20) + User 4 (20) -> Contract (30) + Contract (10)
                    inputs: [
                        UTXO::new(4, 20),
                        UTXO::new(4, 20),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    outputs: [
                        UTXO::new(0, 30),
                        UTXO::new(0, 10),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    nonce: Nonce(0),
                },
            ],
            vec![
                Transaction {
                    // User 1 (30) -> User 1 (20) + User 3 (10)
                    inputs: [
                        UTXO::new(1, 30),
                        UTXO::dummy(),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    outputs: [
                        UTXO::new(1, 20),
                        UTXO::new(3, 10),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    nonce: Nonce(1),
                },
                Transaction {
                    // User 3 (30) -> User 3 (10) + User 2 (40)
                    inputs: [
                        UTXO::new(3, 30),
                        UTXO::new(3, 10),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    outputs: [
                        UTXO::new(2, 40),
                        UTXO::dummy(),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    nonce: Nonce(1),
                },
            ],
        );
    }

    #[should_panic]
    #[test]
    fn test_aggregator_native_invalid_nonce() {
        test_aggregator_native(
            vec![
                Transaction {
                    // Contract (80) + Contract (20) -> User 1 (100)
                    inputs: [
                        UTXO::new(0, 80),
                        UTXO::new(0, 20),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    outputs: [
                        UTXO::new(1, 100),
                        UTXO::dummy(),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    nonce: Nonce(0),
                },
                Transaction {
                    // User 1 (100) -> User 2 (30) + User 3 (40) + User 1 (30)
                    inputs: [
                        UTXO::new(1, 100),
                        UTXO::dummy(),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    outputs: [
                        UTXO::new(2, 30),
                        UTXO::new(3, 40),
                        UTXO::new(1, 30),
                        UTXO::dummy(),
                    ],
                    nonce: Nonce(0),
                },
                Transaction {
                    // User 2 (30) -> User 3 (10) + User 4 (20)
                    inputs: [
                        UTXO::new(2, 30),
                        UTXO::dummy(),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    outputs: [
                        UTXO::new(3, 10),
                        UTXO::new(4, 20),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    nonce: Nonce(0),
                },
                Transaction {
                    // User 3 (40) + User 3 (10) -> User 4 (20) + User 3 (30)
                    inputs: [
                        UTXO::new(3, 40),
                        UTXO::new(3, 10),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    outputs: [
                        UTXO::new(4, 20),
                        UTXO::new(3, 30),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    nonce: Nonce(0),
                },
                Transaction {
                    // User 4 (20) + User 4 (20) -> Contract (30) + Contract (10)
                    inputs: [
                        UTXO::new(4, 20),
                        UTXO::new(4, 20),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    outputs: [
                        UTXO::new(0, 30),
                        UTXO::new(0, 10),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    nonce: Nonce(0),
                },
            ],
            vec![
                Transaction {
                    // User 1 (30) -> User 1 (20) + User 3 (10)
                    inputs: [
                        UTXO::new(1, 30),
                        UTXO::dummy(),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    outputs: [
                        UTXO::new(1, 20),
                        UTXO::new(3, 10),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    nonce: Nonce(1),
                },
                Transaction {
                    // User 3 (30) -> User 3 (10) + User 2 (40)
                    inputs: [
                        UTXO::new(3, 30),
                        UTXO::new(3, 10),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    outputs: [
                        UTXO::new(2, 40),
                        UTXO::dummy(),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    nonce: Nonce(2), // <---
                },
            ],
        );
    }

    #[should_panic]
    #[test]
    fn test_aggregator_native_invalid_utxo() {
        test_aggregator_native(
            vec![
                Transaction {
                    // Contract (80) + Contract (20) -> User 1 (100)
                    inputs: [
                        UTXO::new(0, 80),
                        UTXO::new(0, 20),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    outputs: [
                        UTXO::new(1, 100),
                        UTXO::dummy(),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    nonce: Nonce(0),
                },
                Transaction {
                    // User 1 (100) -> User 2 (30) + User 3 (40) + User 1 (30)
                    inputs: [
                        UTXO::new(1, 100),
                        UTXO::dummy(),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    outputs: [
                        UTXO::new(2, 30),
                        UTXO::new(3, 40),
                        UTXO::new(1, 30),
                        UTXO::dummy(),
                    ],
                    nonce: Nonce(0),
                },
                Transaction {
                    // User 2 (30) -> User 3 (10) + User 4 (20)
                    inputs: [
                        UTXO::new(2, 30),
                        UTXO::dummy(),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    outputs: [
                        UTXO::new(3, 10),
                        UTXO::new(4, 20),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    nonce: Nonce(0),
                },
                Transaction {
                    // User 3 (40) + User 3 (10) -> User 4 (20) + User 3 (30)
                    inputs: [
                        UTXO::new(3, 40),
                        UTXO::new(3, 10),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    outputs: [
                        UTXO::new(4, 20),
                        UTXO::new(3, 30),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    nonce: Nonce(0),
                },
                Transaction {
                    // User 4 (20) + User 4 (20) -> Contract (30) + Contract (10)
                    inputs: [
                        UTXO::new(4, 20),
                        UTXO::new(4, 20),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    outputs: [
                        UTXO::new(0, 30),
                        UTXO::new(0, 10),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    nonce: Nonce(0),
                },
            ],
            vec![
                Transaction {
                    // User 1 (30) -> User 1 (20) + User 3 (10)
                    inputs: [
                        UTXO::new(1, 20), // <---
                        UTXO::dummy(),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    outputs: [
                        UTXO::new(1, 10),
                        UTXO::new(3, 10),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    nonce: Nonce(1),
                },
                Transaction {
                    // User 3 (30) -> User 3 (10) + User 2 (40)
                    inputs: [
                        UTXO::new(3, 30),
                        UTXO::new(3, 10),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    outputs: [
                        UTXO::new(2, 40),
                        UTXO::dummy(),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    nonce: Nonce(1),
                },
            ],
        );
    }

    #[should_panic]
    #[test]
    fn test_aggregator_native_invalid_sum() {
        test_aggregator_native(
            vec![
                Transaction {
                    // Contract (80) + Contract (20) -> User 1 (100)
                    inputs: [
                        UTXO::new(0, 80),
                        UTXO::new(0, 20),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    outputs: [
                        UTXO::new(1, 100),
                        UTXO::dummy(),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    nonce: Nonce(0),
                },
                Transaction {
                    // User 1 (100) -> User 2 (30) + User 3 (40) + User 1 (30)
                    inputs: [
                        UTXO::new(1, 100),
                        UTXO::dummy(),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    outputs: [
                        UTXO::new(2, 30),
                        UTXO::new(3, 40),
                        UTXO::new(1, 30),
                        UTXO::dummy(),
                    ],
                    nonce: Nonce(0),
                },
                Transaction {
                    // User 2 (30) -> User 3 (10) + User 4 (20)
                    inputs: [
                        UTXO::new(2, 30),
                        UTXO::dummy(),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    outputs: [
                        UTXO::new(3, 10),
                        UTXO::new(4, 20),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    nonce: Nonce(0),
                },
                Transaction {
                    // User 3 (40) + User 3 (10) -> User 4 (20) + User 3 (30)
                    inputs: [
                        UTXO::new(3, 40),
                        UTXO::new(3, 10),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    outputs: [
                        UTXO::new(4, 20),
                        UTXO::new(3, 30),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    nonce: Nonce(0),
                },
                Transaction {
                    // User 4 (20) + User 4 (20) -> Contract (30) + Contract (10)
                    inputs: [
                        UTXO::new(4, 20),
                        UTXO::new(4, 20),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    outputs: [
                        UTXO::new(0, 30),
                        UTXO::new(0, 10),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    nonce: Nonce(0),
                },
            ],
            vec![
                Transaction {
                    // User 1 (30) -> User 1 (20) + User 3 (10)
                    inputs: [
                        UTXO::new(1, 30),
                        UTXO::dummy(),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    outputs: [
                        UTXO::new(1, 100), // <---
                        UTXO::new(3, 10),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    nonce: Nonce(1),
                },
                Transaction {
                    // User 3 (30) -> User 3 (10) + User 2 (40)
                    inputs: [
                        UTXO::new(3, 30),
                        UTXO::new(3, 10),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    outputs: [
                        UTXO::new(2, 40),
                        UTXO::dummy(),
                        UTXO::dummy(),
                        UTXO::dummy(),
                    ],
                    nonce: Nonce(1),
                },
            ],
        );
    }
}
