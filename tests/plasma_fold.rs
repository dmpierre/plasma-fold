#![cfg(target_arch = "wasm32")]
wasm_bindgen_test_configure!(run_in_browser);

extern crate wasm_bindgen_test;
use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::{
        poseidon::constraints::CRHParametersVar,
        sha256::{self, constraints::UnitVar},
        TwoToOneCRHSchemeGadget,
    },
    sponge::Absorb,
};
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

use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{AllocVar, Boolean, ToBitsGadget, ToBytesGadget},
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

    SchnorrGadget::verify::<W, _, _>(&pp, &pk, m, (s, e)).unwrap();
    console_log!("num_constraints: {}", cs.num_constraints());
    console_log!("is_satisfied: {}", cs.is_satisfied().unwrap());
}

#[wasm_bindgen_test]
pub fn test_keypair() {
    const W: usize = 32;
    let cs = ConstraintSystem::<Fr>::new_ref();
    let rng = &mut thread_rng();
    let pp = poseidon_canonical_config::<Fr>();
    let KeyPair { sk, pk } = KeyPair::<Projective>::new(rng);
    let m = Fr::rand(rng);
    let signature = sk.sign::<Projective>(&pp, m, rng).unwrap();
    assert!(pk.verify_signature(&pp, m, &signature).unwrap());

    let pp = CRHParametersVar::new_constant(cs.clone(), pp).unwrap();
    let pk_var_point = GVar::new_witness(cs.clone(), || Ok(pk.key)).unwrap();
    let pk_var = PublicKeyVar {
        key: pk_var_point,
        _f: PhantomData::<Projective>,
    };
    let m = FpVar::new_witness(cs.clone(), || Ok(m)).unwrap();

    let sig_var = SignatureVar::new_witness(cs.clone(), || Ok(signature)).unwrap();

    pk_var.verify_signature::<W>(&pp, m, sig_var).unwrap();

    console_log!("num_constraints: {}", cs.num_constraints());
    console_log!("is_satisfied: {}", cs.is_satisfied().unwrap());
}

#[wasm_bindgen_test]
pub fn test_constraints_sha256() {
    let cs = ConstraintSystem::<Fr>::new_ref();
    let rng = &mut thread_rng();

    let a = FpVar::new_witness(cs.clone(), || Ok(Fr::rand(rng))).unwrap();
    let b = FpVar::new_witness(cs.clone(), || Ok(Fr::rand(rng))).unwrap();
    let unit_var = UnitVar::default();
    let res = Sha256Gadget::evaluate(
        &unit_var,
        a.to_bytes_le().unwrap().as_slice(),
        b.to_bytes_le().unwrap().as_slice(),
    )
    .unwrap();

    console_log!("sha256 num_constraints: {}", cs.num_constraints());
    console_log!("sha256 is_satisfied: {}", cs.is_satisfied().unwrap());
}
