use ark_bn254::Fr;
use ark_crypto_primitives::crh::poseidon::constraints::TwoToOneCRHGadget;
use ark_crypto_primitives::crh::poseidon::TwoToOneCRH;
use ark_crypto_primitives::crh::{
    poseidon::constraints::CRHParametersVar, sha256::constraints::UnitVar,
};
use ark_grumpkin::constraints::GVar;
use ark_grumpkin::Projective;
use ark_r1cs_std::alloc::AllocVar;
use ark_relations::r1cs::ConstraintSystem;
use client::circuits::{UserAux, UserCircuit};
use folding_schemes::transcript::poseidon::poseidon_canonical_config;
use plasma_fold::primitives::accumulator::constraints::PoseidonAccumulatorVar;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
pub fn user_circuit_poseidon_n_constraints() {
    let pos_params = poseidon_canonical_config();
    let cs = ConstraintSystem::<Fr>::new_ref();
    let acc_pp = UnitVar::new_constant(cs.clone(), ()).unwrap();
    let pos_pp = CRHParametersVar::new_constant(cs.clone(), pos_params).unwrap();
    let user_circuit = UserCircuit::<
        _,
        Projective,
        GVar,
        TwoToOneCRH<_>,
        TwoToOneCRHGadget<_>,
        PoseidonAccumulatorVar<_>,
    >::new(pos_pp.clone(), pos_pp);

    let user_aux = UserAux {
        tx_inclusion_proof: todo!(),
        signer_pk_inclusion_proof: todo!(),
        block: todo!(),
        transaction: todo!(),
        pk: todo!(),
    };

    console_log!("n constraints: {}", cs.num_constraints());
}
