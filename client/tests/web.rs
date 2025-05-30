use std::collections::BTreeMap;

use ark_bn254::Fr;
use ark_crypto_primitives::crh::poseidon::constraints::TwoToOneCRHGadget;
use ark_crypto_primitives::crh::poseidon::TwoToOneCRH;
use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
use ark_crypto_primitives::crh::sha256::Sha256;
use ark_crypto_primitives::crh::CRHScheme;
use ark_crypto_primitives::crh::{
    poseidon::constraints::CRHParametersVar, sha256::constraints::UnitVar,
};
use ark_ff::{AdditiveGroup, Field};
use ark_grumpkin::constraints::GVar;
use ark_grumpkin::Projective;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::ConstraintSystem;
use ark_std::rand::thread_rng;
use client::circuits::{UserAux, UserAuxVar, UserCircuit};
use folding_schemes::transcript::poseidon::poseidon_canonical_config;
use plasma_fold::datastructures::block::Block;
use plasma_fold::datastructures::keypair::KeyPair;
use plasma_fold::datastructures::noncemap::Nonce;
use plasma_fold::datastructures::signerlist::{SignerTree, SignerTreeConfig};
use plasma_fold::datastructures::transaction::{
    Transaction, TransactionTree, TransactionTreeConfig,
};
use plasma_fold::datastructures::user::User;
use plasma_fold::datastructures::utxo::{UTXOTree, UTXOTreeConfig, UTXO};
use plasma_fold::primitives::accumulator::constraints::PoseidonAccumulatorVar;
use plasma_fold::primitives::crh::PublicKeyCRH;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

pub fn generate_user_aux_data() -> UserAux<Fr, Projective> {
    let pp = poseidon_canonical_config();
    let mut rng = thread_rng();

    // Build user
    let user = User::<Projective>::new(&mut rng, 42);

    // Build utxo tree, doesn't need to store any utxo
    let utxo_tree_root = UTXOTree::<UTXOTreeConfig<Projective>>::blank(&pp, &pp).root();

    let mut signer_leaves = BTreeMap::new();
    signer_leaves.insert(user.id as u64, user.keypair.pk);
    let signer_tree =
        SignerTree::<SignerTreeConfig<Projective>>::new(&pp, &pp, &signer_leaves).unwrap();

    let signer_inclusion_proof = signer_tree
        .generate_proof(user.id as u64, &user.keypair.pk)
        .unwrap();

    // Build tx tree
    let tx_tree_height = 10;
    let n_transactions = (2 as usize).pow(tx_tree_height);
    let mut transactions = (0..n_transactions)
        .map(|_| Transaction::default())
        .collect::<Vec<Transaction<Projective>>>();

    let tx = Transaction {
        inputs: [
            UTXO::new(user.keypair.pk, 80),
            UTXO::new(user.keypair.pk, 20),
            UTXO::dummy(),
            UTXO::dummy(),
        ],
        outputs: [
            UTXO::new(KeyPair::new(&mut rng).pk, 100),
            UTXO::dummy(),
            UTXO::dummy(),
            UTXO::dummy(),
        ],
        nonce: Nonce(0),
    };

    let tx_index = transactions.len() - 1;
    transactions.pop();
    transactions.push(tx.clone());

    let tx_tree = TransactionTree::<TransactionTreeConfig<Projective>>::new(
        &pp,
        &pp,
        &BTreeMap::from_iter(
            transactions
                .iter()
                .enumerate()
                .map(|(i, tx)| (i as u64, tx.clone())),
        ),
    )
    .unwrap();

    let tx_inclusion_proof = tx_tree.generate_proof(tx_index as u64, &tx).unwrap();

    let block = Block {
        utxo_tree_root,
        tx_tree_root: tx_tree.root(),
        signer_tree_root: signer_tree.root(),
        signers: Vec::from([Some(user.id)]),
        number: Fr::ONE,
    };

    let user_aux = UserAux {
        tx_inclusion_proof,
        signer_pk_inclusion_proof: signer_inclusion_proof,
        block,
        transaction: (tx, Fr::from(tx_index as u64)),
        pk: user.keypair.pk,
    };

    user_aux
}

#[wasm_bindgen_test]
pub fn user_circuit_poseidon_n_constraints() {
    let user_aux = generate_user_aux_data();
    let pos_params = poseidon_canonical_config();
    let cs = ConstraintSystem::<Fr>::new_ref();
    let pos_pp = CRHParametersVar::new_constant(cs.clone(), pos_params.clone()).unwrap();
    let user_circuit = UserCircuit::<
        _,
        Projective,
        GVar,
        TwoToOneCRH<_>,
        TwoToOneCRHGadget<_>,
        PoseidonAccumulatorVar<_>,
    >::new(pos_pp.clone(), pos_pp);
    let mut z_i = Vec::<FpVar<Fr>>::new();
    let pk_hash = PublicKeyCRH::evaluate(&pos_params, user_aux.pk).unwrap();

    z_i.push(FpVar::new_witness(cs.clone(), || Ok(Fr::ZERO)).unwrap());
    z_i.push(FpVar::new_witness(cs.clone(), || Ok(Fr::ZERO)).unwrap());
    z_i.push(FpVar::new_witness(cs.clone(), || Ok(pk_hash)).unwrap());
    z_i.push(FpVar::new_witness(cs.clone(), || Ok(Fr::ZERO)).unwrap());
    z_i.push(FpVar::new_witness(cs.clone(), || Ok(Fr::ZERO)).unwrap());
    z_i.push(FpVar::new_witness(cs.clone(), || Ok(Fr::ZERO)).unwrap());
    z_i.push(FpVar::new_witness(cs.clone(), || Ok(Fr::ZERO)).unwrap());

    let user_aux_var = UserAuxVar::new_witness(cs.clone(), || Ok(user_aux)).unwrap();
    user_circuit
        .update_balance(cs.clone(), z_i, user_aux_var)
        .unwrap();
    console_log!("n constraints: {}", cs.num_constraints());
}
