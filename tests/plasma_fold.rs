#![cfg(target_arch = "wasm32")]
wasm_bindgen_test_configure!(run_in_browser);

extern crate wasm_bindgen_test;
use ark_bn254::Fr;
use ark_crypto_primitives::sponge::Absorb;
use folding_schemes::transcript::poseidon::poseidon_canonical_config;
use plasma_fold::datastructures::transaction::{Transaction, TransactionTreeConfig};
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
pub fn test_tx_tree_init() {
    let config = TransactionTreeConfig {
        poseidon_conf: poseidon_canonical_config::<Fr>(),
    };
    let tx = Transaction::<Fr>::default();
    let mut dest = Vec::new();
    tx.to_sponge_bytes(&mut dest);
    console_log!("length: {}", dest.len());
    // TransactionTree::new(&config.poseidon_conf, &config.poseidon_conf, &tx_arr);
}
