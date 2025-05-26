use ark_crypto_primitives::merkle_tree::Config;
use ark_ff::PrimeField;

use super::utxo::UTXO;

pub mod constraints;

// contains the roots of utxo, transaction, signer, deposit and withdraw trees
pub struct Block<F: PrimeField> {
    pub utxo_tree_root: F,
    pub tx_tree_root: F,
    pub signer_tree_root: F,
    // the list of signer ids
    pub signers: Vec<Option<u32>>,
    pub deposits: Vec<UTXO>,
    pub withdrawals: Vec<UTXO>,
}
