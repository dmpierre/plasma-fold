#![cfg(target_arch = "wasm32")]
wasm_bindgen_test_configure!(run_in_browser);

extern crate wasm_bindgen_test;
use plasma_fold::circuits::tests::{
    test_asset_tree_is_not_updated_with_wrong_deposit, test_plasmafold_circuit,
};
use wasm_bindgen_test::*;
use web_sys::console;

#[wasm_bindgen_test]
pub fn test_plasma_fold() {
    console::log_2(
        &"PlasmaFold passed: ".into(),
        &test_plasmafold_circuit().to_string().into(),
    );
    console::log_2(
        &"PlasmaFold asset tree not updated with no deposit: ".into(),
        &test_asset_tree_is_not_updated_with_wrong_deposit()
            .to_string()
            .into(),
    );
}
