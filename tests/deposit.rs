#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use wasm_bindgen_test::*;
use web_sys::console;
wasm_bindgen_test_configure!(run_in_browser);

use plasma_fold::circuits::{
    deposit::tests::{
        test_deposit_false_deposit_flag_false, test_deposit_true_deposit_flag_false,
        test_deposit_true_deposit_flag_true,
    },
    tests::test_n_constraints,
};

#[wasm_bindgen_test]
pub fn test_deposit() {
    console::log_2(
        &"test_deposit_true_deposit_flag_true: ".into(),
        &test_deposit_true_deposit_flag_true().to_string().into(),
    );
    console::log_2(
        &" test_deposit_true_deposit_flag_false passed: ".into(),
        &test_deposit_true_deposit_flag_false().to_string().into(),
    );
    console::log_2(
        &"test_deposit_false_deposit_flag_false passed: ".into(),
        &test_deposit_false_deposit_flag_false().to_string().into(),
    );
}
