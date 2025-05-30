use ark_bn254::Fr;
use ark_crypto_primitives::crh::{
    poseidon::{
        constraints::{CRHParametersVar, TwoToOneCRHGadget},
        TwoToOneCRH,
    },
    CRHScheme,
};
use ark_ff::{AdditiveGroup, Field};
use ark_grumpkin::{constraints::GVar, Projective};
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
use ark_relations::r1cs::ConstraintSystem;
use ark_std::rand::thread_rng;
use client::{
    circuits::{UserAux, UserAuxVar, UserCircuit},
    N_TX_PER_FOLD_STEP,
};
use folding_schemes::folding::traits::Dummy;
use folding_schemes::transcript::poseidon::poseidon_canonical_config;
use plasma_fold::{
    datastructures::{
        block::Block,
        keypair::{KeyPair, PublicKey},
        noncemap::Nonce,
        signerlist::{SignerTree, SignerTreeConfig},
        transaction::{Transaction, TransactionTree, TransactionTreeConfig},
        user::User,
        utxo::{UTXOTree, UTXOTreeConfig, UTXO},
    },
    primitives::{accumulator::constraints::PoseidonAccumulatorVar, crh::PublicKeyCRH},
};
use std::collections::BTreeMap;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

// Generates user aux data for one correct transaction among N_TX_PER_FOLD_STEP
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
    let mut signer_pk_inclusion_proofs = Vec::new();

    signer_pk_inclusion_proofs.push(
        signer_tree
            .generate_proof(user.id as u64, &user.keypair.pk)
            .unwrap(),
    );
    for _ in 1..N_TX_PER_FOLD_STEP {
        signer_pk_inclusion_proofs.push(
            signer_tree
                .generate_proof(0, &PublicKey::default())
                .unwrap(),
        );
    }

    // Build tx tree, 10 transactions, with 1 not a dummy, made by user
    let n_transactions = 10;
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

    let mut transaction_inclusion_proofs = Vec::new();
    transaction_inclusion_proofs.push(tx_tree.generate_proof(tx_index as u64, &tx).unwrap());
    for _ in 1..N_TX_PER_FOLD_STEP {
        transaction_inclusion_proofs.push(
            tx_tree
                .generate_proof(0 as u64, &Transaction::dummy(()))
                .unwrap(),
        );
    }

    let mut transactions = Vec::new();
    transactions.push((tx, Fr::from(tx_index as u64)));
    for _ in 1..N_TX_PER_FOLD_STEP {
        transactions.push((Transaction::dummy(()), Fr::ZERO));
    }

    let block = Block {
        utxo_tree_root,
        tx_tree_root: tx_tree.root(),
        signer_tree_root: signer_tree.root(),
        signers: Vec::from([Some(user.id)]),
        number: Fr::ONE,
    };

    let user_aux = UserAux {
        transaction_inclusion_proofs,
        signer_pk_inclusion_proofs,
        block,
        transactions,
        pk: user.keypair.pk,
    };

    user_aux
}

#[wasm_bindgen_test]
pub fn test_process_correct_send_transaction() {
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

    z_i.push(FpVar::new_witness(cs.clone(), || Ok(Fr::from(1000 as u64))).unwrap());
    z_i.push(FpVar::new_witness(cs.clone(), || Ok(Fr::ZERO)).unwrap());
    z_i.push(FpVar::new_witness(cs.clone(), || Ok(pk_hash)).unwrap());
    z_i.push(FpVar::new_witness(cs.clone(), || Ok(Fr::ZERO)).unwrap());
    z_i.push(FpVar::new_witness(cs.clone(), || Ok(Fr::ZERO)).unwrap());
    z_i.push(FpVar::new_witness(cs.clone(), || Ok(Fr::ZERO)).unwrap());
    z_i.push(FpVar::new_witness(cs.clone(), || Ok(Fr::ZERO)).unwrap());

    let user_aux_var = UserAuxVar::new_witness(cs.clone(), || Ok(user_aux.clone())).unwrap();
    let new_state = user_circuit
        .update_balance(cs.clone(), z_i.clone(), user_aux_var)
        .unwrap();
    assert!(cs.is_satisfied().unwrap());

    // balance should be updated by transaction sent amount
    let new_bal = new_state[0].clone();
    assert_eq!(
        new_bal.value().unwrap(),
        z_i[0].value().unwrap() - Fr::from(100)
    );

    // nonce should be incremented by one
    let new_nonce = new_state[1].clone();
    assert_eq!(
        new_nonce.value().unwrap(),
        z_i[1].value().unwrap() + Fr::ONE
    );

    // pk hash should be unchanged
    let pk_hash = new_state[2].clone();
    assert_eq!(pk_hash.value().unwrap(), z_i[2].clone().value().unwrap());

    // acc should be updated
    let new_acc = new_state[3].clone();
    assert_ne!(new_acc.value().unwrap(), z_i[3].clone().value().unwrap());

    // block hash should be updated
    let new_block_hash = new_state[4].clone();
    assert_ne!(
        new_block_hash.value().unwrap(),
        z_i[4].clone().value().unwrap()
    );

    // block num should be updated
    let new_block_num = new_state[5].clone();
    assert_ne!(
        new_block_num.value().unwrap(),
        z_i[5].clone().value().unwrap()
    );

    // should be index of last "regular" processed tx
    let new_processed_tx_index = new_state[6].clone();
    assert_eq!(
        new_processed_tx_index.value().unwrap(),
        // the "regular transaction" is the first one in the vector of transactions
        user_aux.transactions[0].1
    );

    console_log!("n constraints: {}", cs.num_constraints());
}
