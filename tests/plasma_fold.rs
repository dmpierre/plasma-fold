#![cfg(target_arch = "wasm32")]
wasm_bindgen_test_configure!(run_in_browser);

extern crate wasm_bindgen_test;
use wasm_bindgen_test::*;
use web_sys::console;

use plasma_fold::circuits::tests::{
    test_balance_is_not_negative, test_n_constraints, test_public_state_is_enforced,
};

#[wasm_bindgen_test]
pub fn test_plasma_fold() {
    console::log_2(
        &"PlasmaFold n_constraints: ".into(),
        &test_n_constraints().to_string().into(),
    );

    console::log_2(
        &"PlasmaFold balance can not be negative: ".into(),
        &test_balance_is_not_negative().to_string().into(),
    );

    console::log_2(
        &"PlasmaFold public state is enforced: ".into(),
        &test_public_state_is_enforced().to_string().into(),
    );
}
