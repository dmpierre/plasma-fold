#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use folding_schemes::transcript::poseidon::poseidon_canonical_config;
    use plasma_fold::datastructures::transaction::{
        Transaction, TransactionTree, TransactionTreeConfig,
    };

    #[test]
    pub fn incr_build_transaction_tree() {
        let tx_tree_height = 10;
        let n_transactions = (2 as usize).pow(tx_tree_height);
        let tx_tree_conf = TransactionTreeConfig {
            poseidon_conf: poseidon_canonical_config(),
        };
        let transactions = (0..n_transactions)
            .map(|_| Transaction::default())
            .collect::<Vec<Transaction>>();
        let tx_tree = TransactionTree::<TransactionTreeConfig<Fr>>::new(
            &tx_tree_conf.poseidon_conf,
            &tx_tree_conf.poseidon_conf,
            transactions,
        )
        .unwrap();
    }
}
