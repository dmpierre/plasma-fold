#![cfg(target_arch = "wasm32")]
wasm_bindgen_test_configure!(run_in_browser);

extern crate wasm_bindgen_test;
use std::marker::PhantomData;

use ark_crypto_primitives::{crh::poseidon::constraints::CRHParametersVar, sponge::Absorb};
use folding_schemes::transcript::poseidon::poseidon_canonical_config;
use plasma_fold::{
    datastructures::{
        keypair::{KeyPair, PublicKeyVar, SignatureVar},
        transaction::{Transaction, TransactionTreeConfig},
    },
    primitives::schnorr::{Schnorr, SchnorrGadget},
};
use wasm_bindgen_test::{console_log, wasm_bindgen_test, wasm_bindgen_test_configure};

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_grumpkin::constraints::GVar;
use ark_grumpkin::Projective;

use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{AllocVar, Boolean},
};
use ark_relations::r1cs::ConstraintSystem;
use ark_std::rand::thread_rng;

#[wasm_bindgen_test]
pub fn test_absorb_transaction() {
    let config = TransactionTreeConfig {
        poseidon_conf: poseidon_canonical_config::<Fr>(),
    };
    let tx = Transaction::<Fr>::default();
    let mut dest = Vec::new();
    tx.to_sponge_bytes(&mut dest);
    console_log!("length: {}", dest.len());

    let mut dest = Vec::<Fr>::new();
    tx.to_sponge_field_elements(&mut dest);
    console_log!("length: {}", dest.len());
}

#[wasm_bindgen_test]
pub fn test_signature() {
    const W: usize = 32;
    let cs = ConstraintSystem::<Fr>::new_ref();

    let rng = &mut thread_rng();

    let pp = poseidon_canonical_config();
    let (sk, pk) = Schnorr::key_gen::<Projective>(rng);
    let m = Fr::rand(rng);
    let (s, e) = Schnorr::sign::<Projective>(&pp, sk, m, rng).unwrap();
    assert!(Schnorr::verify(&pp, &pk, m, (s, e)).unwrap());

    let pp = CRHParametersVar::new_constant(cs.clone(), pp).unwrap();
    let pk = GVar::new_witness(cs.clone(), || Ok(pk)).unwrap();
    let m = FpVar::new_witness(cs.clone(), || Ok(m)).unwrap();
    let s = Vec::new_witness(cs.clone(), || Ok(s.into_bigint().to_bits_le())).unwrap();
    let e = Vec::new_witness(cs.clone(), || Ok(e.into_bigint().to_bits_le())).unwrap();

    SchnorrGadget::verify::<W, _, _>(&pp, pk, m, (s, e)).unwrap();
    console_log!("num_constraints: {}", cs.num_constraints());
    console_log!("is_satisfied: {}", cs.is_satisfied().unwrap());
}

#[wasm_bindgen_test]
pub fn test_keypair() {
    const W: usize = 32;
    let cs = ConstraintSystem::<Fr>::new_ref();
    let rng = &mut thread_rng();
    let pp = poseidon_canonical_config::<Fr>();
    let keypair = KeyPair::<Projective>::new(rng);
    let m = Fr::rand(rng);
    let signature = keypair.sign(&pp, m, rng).unwrap();
    assert!(keypair.pk.verify_signature(&pp, m, signature).unwrap());

    let pp = CRHParametersVar::new_constant(cs.clone(), pp).unwrap();
    let pk_var_point = GVar::new_witness(cs.clone(), || Ok(keypair.pk.key)).unwrap();
    let pk_var = PublicKeyVar {
        key: pk_var_point,
        _f: PhantomData::<Projective>,
    };
    let m = FpVar::new_witness(cs.clone(), || Ok(m)).unwrap();

    let s = Vec::new_witness(cs.clone(), || Ok(signature.0.into_bigint().to_bits_le())).unwrap();
    let e = Vec::new_witness(cs.clone(), || Ok(signature.1.into_bigint().to_bits_le())).unwrap();
    let sig_var: SignatureVar<Projective> = (s, e);

    pk_var.verify_signature::<W>(&pp, m, sig_var).unwrap();

    console_log!("num_constraints: {}", cs.num_constraints());
    console_log!("is_satisfied: {}", cs.is_satisfied().unwrap());
}
