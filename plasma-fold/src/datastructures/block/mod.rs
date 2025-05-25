use ark_crypto_primitives::merkle_tree::Config;
use ark_ff::PrimeField;

use super::{user::UserId, utxo::UTXO};

// contains the roots of utxo, transaction, signer, deposit and withdraw trees
pub struct Block<F: PrimeField> {
    pub utxo_tree_root: F,
    pub tx_tree_root: F,
    pub signers: Vec<Option<UserId>>,
    pub deposits: Vec<UTXO>,
    pub withdrawals: Vec<UTXO>,
}
