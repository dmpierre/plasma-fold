use ark_ff::PrimeField;

pub mod constraints;

// contains the roots of utxo, transaction, signer, deposit and withdraw trees
#[derive(Clone)]
pub struct Block<F: PrimeField> {
    pub utxo_tree_root: F,
    pub tx_tree_root: F,
    pub signer_tree_root: F,
    // the list of signer ids
    pub signers: Vec<Option<u32>>,
    pub number: F, // pub deposits: Vec<UTXO<C>>,
                   // pub withdrawals: Vec<UTXO<C>>,
}
