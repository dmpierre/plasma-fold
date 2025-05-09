mod utils;

use ark_grumpkin::Projective;
use plasma_fold::datastructures::keypair::KeyPair;
use wasm_bindgen::prelude::*;

pub fn some_test() {
    let keypair: KeyPair<Projective> = KeyPair {
        sk: todo!(),
        pk: todo!(),
    };
}

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

#[wasm_bindgen]
pub fn greet() {
    alert("Hello, client!");
}
