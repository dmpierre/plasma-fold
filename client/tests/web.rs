use ark_bn254::Fr;
use ark_crypto_primitives::crh::poseidon::constraints::TwoToOneCRHGadget;
use ark_crypto_primitives::crh::poseidon::TwoToOneCRH;
use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
use ark_crypto_primitives::crh::sha256::Sha256;
use ark_crypto_primitives::crh::{
    poseidon::constraints::CRHParametersVar, sha256::constraints::UnitVar,
};
use ark_grumpkin::constraints::GVar;
use ark_grumpkin::Projective;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::ConstraintSystem;
use client::circuits::{UserAux, UserAuxVar, UserCircuit};
use folding_schemes::transcript::poseidon::poseidon_canonical_config;
use plasma_fold::primitives::accumulator::constraints::PoseidonAccumulatorVar;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
pub fn user_circuit_poseidon_n_constraints() {
    let pos_params = poseidon_canonical_config();
    let cs = ConstraintSystem::<Fr>::new_ref();
    let pos_pp = CRHParametersVar::new_constant(cs.clone(), pos_params).unwrap();

    // define circuit, aux state and z_i
    let user_circuit = UserCircuit::<
        _,
        Projective,
        GVar,
        TwoToOneCRH<_>,
        TwoToOneCRHGadget<_>,
        PoseidonAccumulatorVar<_>,
    >::new(pos_pp.clone(), pos_pp);
    let user_aux = UserAuxVar::<Fr, Projective, GVar>::new();
    let z_i = Vec::<FpVar<Fr>>::new();

    user_circuit
        .update_balance(cs.clone(), z_i, user_aux)
        .unwrap();

    console_log!("n constraints: {}", cs.num_constraints());
}
