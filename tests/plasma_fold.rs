#![cfg(target_arch = "wasm32")]
wasm_bindgen_test_configure!(run_in_browser);

extern crate wasm_bindgen_test;
use ark_crypto_primitives::{crh::poseidon::constraints::CRHParametersVar, sponge::Absorb};
use ark_ec::AffineRepr;
use folding_schemes::transcript::poseidon::poseidon_canonical_config;
use plasma_fold::{
    datastructures::transaction::{Transaction, TransactionTreeConfig},
    primitives::schnorr::{Schnorr, SchnorrGadget},
};
use wasm_bindgen_test::*;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_grumpkin::{constraints::GVar, Affine};
use ark_r1cs_std::{fields::fp::FpVar, prelude::AllocVar};
use ark_relations::r1cs::ConstraintSystem;
use ark_std::rand::thread_rng;
use num::{BigUint, Zero};

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

#[wasm_bindgen_test]
pub fn test_signature() {
    const W: usize = 32;
    let cs = ConstraintSystem::<Fr>::new_ref();

    let rng = &mut thread_rng();

    let pp = poseidon_canonical_config();
    let (sk, pk) = Schnorr::key_gen::<Affine, _>(rng);
    let m = Fr::rand(rng);
    let (s, e) = Schnorr::sign::<Affine, _, _, _>(&pp, sk, m, rng).unwrap();
    assert!(Schnorr::verify(&pp, &pk, m, (s, e)).unwrap());

    let pp = CRHParametersVar::new_constant(cs.clone(), pp).unwrap();
    let pk = GVar::new_witness(cs.clone(), || Ok(pk.into_group())).unwrap();
    let m = FpVar::new_witness(cs.clone(), || Ok(m)).unwrap();
    let s = Vec::new_witness(cs.clone(), || Ok(s.into_bigint().to_bits_le())).unwrap();
    let e = Vec::new_witness(cs.clone(), || Ok(e.into_bigint().to_bits_le())).unwrap();
    SchnorrGadget::verify::<W, _, _>(&pp, pk, m, (s, e)).unwrap();

    console_log!("num_constraints: {}", cs.num_constraints());
    console_log!("is_satisfied: {}", cs.is_satisfied().unwrap());
}
