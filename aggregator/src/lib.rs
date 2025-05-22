use std::collections::HashMap;

use ark_crypto_primitives::sponge::{poseidon::PoseidonConfig, Absorb};
use ark_ff::PrimeField;
use plasma_fold::datastructures::{
    block::Block, noncemap::{Nonce, NonceTree, NonceTreeConfig}, transaction::{Transaction, TransactionTree, TransactionTreeConfig}, user::{UserId, ROLLUP_CONTRACT_ID}, utxo::{UTXOTree, UTXOTreeConfig, UTXO}
};

pub mod circuit;

pub struct AggregatorState<F: PrimeField + Absorb> {
    pub config: PoseidonConfig<F>,

    pub utxos: Vec<UTXO>,
    pub utxo_tree: UTXOTree<UTXOTreeConfig<F>>,
    pub transactions: Vec<Transaction>,
    pub transaction_tree: TransactionTree<TransactionTreeConfig<F>>,
    pub nonces: HashMap<UserId, Nonce>,
    pub nonce_tree: NonceTree<NonceTreeConfig<F>>,
    pub deposits: Vec<UTXO>,
    pub withdrawals: Vec<UTXO>,
    pub signers: Vec<UserId>,

    pub acc_signer: F,
    pub acc_pk: F,
}

impl<F: PrimeField + Absorb> AggregatorState<F> {
    pub fn new(config: PoseidonConfig<F>, height: usize) -> Self {
        Self {
            utxos: vec![],
            utxo_tree: UTXOTree::blank(&config, &config, height).unwrap(),
            transactions: vec![],
            transaction_tree: TransactionTree::blank(&config, &config, height).unwrap(),
            nonces: HashMap::new(),
            nonce_tree: NonceTree::blank(&config, &config, height).unwrap(),
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
        self.transaction_tree =
            TransactionTree::blank(&self.config, &self.config, self.transaction_tree.height())
                .unwrap();
        self.deposits.clear();
        self.withdrawals.clear();
        self.signers.clear();
        self.acc_signer = F::zero();
        self.acc_pk = F::zero();
    }

    pub fn add_transaction(&mut self, sender: UserId, tx: Transaction) {
        // Check if tx is valid
        assert!(tx.is_valid(Some(sender), Some(self.nonces[&sender])));

        // Add tx to the transaction tree
        self.transactions.push(tx);
        self.transaction_tree
            .update(
                self.transactions.len() - 1,
                &self.transactions[self.transactions.len() - 1],
            )
            .unwrap();

        for &utxo in tx.inputs.iter().filter(|utxo| !utxo.is_dummy) {
            if utxo.id != ROLLUP_CONTRACT_ID {
                todo!("Ensure input utxo is in the utxo tree");
                todo!("Remove input utxo from the utxo tree");
            }
        }
        for &utxo in tx.outputs.iter().filter(|utxo| !utxo.is_dummy) {
            if sender == ROLLUP_CONTRACT_ID {
                self.deposits.push(utxo);
            }
            if utxo.id != ROLLUP_CONTRACT_ID {
                todo!("Add output utxos to the utxo tree");
            } else {
                self.withdrawals.push(UTXO {
                    amount: utxo.amount,
                    id: sender,
                    is_dummy: false,
                });
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
mod tests {}
