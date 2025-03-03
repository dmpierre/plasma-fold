#![cfg(target_arch = "wasm32")]
wasm_bindgen_test_configure!(run_in_browser);

extern crate wasm_bindgen_test;
use wasm_bindgen_test::*;
use web_sys::console;

use plasma_fold::circuits::tests::test_n_constraints;

#[wasm_bindgen_test]
pub fn test_n_constraints_plasma_fold() {
    console::log_2(
        &"PlasmaFold n_constraints: ".into(),
        &test_n_constraints().to_string().into(),
    );
}
