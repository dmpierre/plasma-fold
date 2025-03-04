#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use wasm_bindgen_test::*;
use web_sys::console;
wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
pub fn test_deposit() {}
