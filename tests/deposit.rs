#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

use plasma_fold::tests::tests::test_deposit;
use web_sys::console;

#[wasm_bindgen_test]
pub fn test_deposit_wasm() {
    let is_satisfied = test_deposit().to_string();
    console::log_2(&"Deposit: ".into(), &is_satisfied.into());
}
