mod circuits;
mod utils;

use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

#[wasm_bindgen]
pub fn greet() {
    alert("Hello, fold-plasma!");
}
