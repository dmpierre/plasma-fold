use ark_bn254::Fr;
use ark_bn254::G1Projective as Projective2;
use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
use ark_crypto_primitives::crh::sha256::constraints::UnitVar;
use ark_crypto_primitives::crh::sha256::Sha256;
use ark_crypto_primitives::{
    crh::{
        poseidon::{
            constraints::{CRHParametersVar, TwoToOneCRHGadget},
            TwoToOneCRH,
        },
        CRHScheme,
    },
    sponge::poseidon::PoseidonConfig,
};
use ark_ff::{AdditiveGroup, Field};
use ark_grumpkin::{constraints::GVar, Projective};
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
use ark_std::rand::thread_rng;
use client::ClientCircuitSha;
use client::{
    circuits::{UserAux, UserAuxVar, UserCircuit},
    ClientCircuitPoseidon,
};
use folding_schemes::commitment::pedersen::Pedersen;
use folding_schemes::FoldingScheme;
use folding_schemes::{
    folding::{
        nova::{Nova, PreprocessorParam},
        traits::Dummy,
    },
    frontend::FCircuit,
    transcript::poseidon::poseidon_canonical_config,
};

use js_sys::{Uint8Array, WebAssembly};
use plasma_fold::primitives::accumulator::constraints::Sha256AccumulatorVar;
use plasma_fold::{
    datastructures::{
        block::Block,
        signerlist::{SignerTree, SignerTreeConfig},
        transaction::{Transaction, TransactionTree, TransactionTreeConfig},
        user::User,
        utxo::UTXO,
    },
    primitives::{
        accumulator::constraints::PoseidonAccumulatorVar,
        crh::{BlockCRH, PublicKeyCRH},
        sparsemt::MerkleSparseTreePath,
    },
};
use std::collections::BTreeMap;
use std::time::Duration;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;
use web_time::Instant;

wasm_bindgen_test_configure!(run_in_browser);

pub fn make_tx(sender: &User<Projective>, receiver: &User<Projective>) -> Transaction<Projective> {
    Transaction {
        inputs: [
            UTXO::new(sender.keypair.pk, 80),
            UTXO::new(sender.keypair.pk, 20),
            UTXO::dummy(),
            UTXO::dummy(),
        ],
        outputs: [
            UTXO::new(receiver.keypair.pk, 100),
            UTXO::dummy(),
            UTXO::dummy(),
            UTXO::dummy(),
        ],
    }
}

pub fn pad_transaction_vec(
    transaction_vec: &mut Vec<(Transaction<Projective>, u64)>,
    n_transactions: usize,
) {
    while transaction_vec.len() < n_transactions {
        transaction_vec.push((Transaction::dummy(()), 0))
    }
}

pub fn get_client_circuit<const BATCH_SIZE: usize>(
    pp_var: &CRHParametersVar<Fr>,
) -> UserCircuit<
    Fr,
    Projective,
    GVar,
    TwoToOneCRH<Fr>,
    TwoToOneCRHGadget<Fr>,
    PoseidonAccumulatorVar<Fr>,
    BATCH_SIZE,
> {
    UserCircuit::<
        Fr,
        Projective,
        GVar,
        TwoToOneCRH<Fr>,
        TwoToOneCRHGadget<Fr>,
        PoseidonAccumulatorVar<Fr>,
        BATCH_SIZE,
    >::new(pp_var.clone(), pp_var.clone())
}

pub fn get_client_circuit_sha<const BATCH_SIZE: usize>(
    cs: ConstraintSystemRef<Fr>,
    pp_var: &CRHParametersVar<Fr>,
) -> UserCircuit<Fr, Projective, GVar, Sha256, Sha256Gadget<Fr>, Sha256AccumulatorVar<Fr>, BATCH_SIZE>
{
    UserCircuit::<
        Fr,
        Projective,
        GVar,
        Sha256,
        Sha256Gadget<Fr>,
        Sha256AccumulatorVar<Fr>,
        BATCH_SIZE,
    >::new(
        UnitVar::new_constant(cs.clone(), ()).unwrap(),
        pp_var.clone(),
    )
}

// make transaction tree from a specified vector of transactions, along with their indexes in the
// transaction tree
pub fn make_tx_tree(
    pp: &PoseidonConfig<Fr>,
    transactions: &Vec<(Transaction<Projective>, u64)>,
) -> TransactionTree<TransactionTreeConfig<Projective>> {
    let leaves = BTreeMap::from_iter(transactions.iter().map(|(tx, i)| (*i, tx.clone())));
    TransactionTree::new(pp, pp, &leaves).unwrap()
}

// build vector consisting in transaction inclusion proofs
pub fn get_tx_inclusion_proofs(
    transactions: &Vec<(Transaction<Projective>, u64)>,
    transaction_tree: &TransactionTree<TransactionTreeConfig<Projective>>,
    n_transactions: usize,
) -> Vec<MerkleSparseTreePath<TransactionTreeConfig<Projective>>> {
    let mut tx_inclusion_proofs = Vec::new();
    for (tx, idx) in transactions {
        tx_inclusion_proofs.push(transaction_tree.generate_proof(*idx, tx).unwrap());
    }
    while tx_inclusion_proofs.len() < n_transactions {
        tx_inclusion_proofs.push(
            transaction_tree
                .generate_proof(transactions[0].1, &transactions[0].0)
                .unwrap(),
        )
    }
    tx_inclusion_proofs
}

// build vector
pub fn get_state_as_var(cs: ConstraintSystemRef<Fr>, state: Vec<Fr>) -> Vec<FpVar<Fr>> {
    Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(state)).unwrap()
}

// make signer tree from a specified vector of users
pub fn make_signer_tree(
    pp: &PoseidonConfig<Fr>,
    users: &Vec<User<Projective>>,
) -> SignerTree<SignerTreeConfig<Projective>> {
    let mut signer_leaves = BTreeMap::new();
    for user in users {
        signer_leaves.insert(user.id as u64, user.keypair.pk);
    }
    SignerTree::<SignerTreeConfig<Projective>>::new(pp, pp, &signer_leaves).unwrap()
}

pub fn get_signer_inclusion_proofs(
    signers: &Vec<User<Projective>>,
    tree: &SignerTree<SignerTreeConfig<Projective>>,
    n_transactions: usize,
) -> Vec<MerkleSparseTreePath<SignerTreeConfig<Projective>>> {
    let mut signer_pk_inclusion_proofs = Vec::new();
    for signer in signers {
        signer_pk_inclusion_proofs.push(
            tree.generate_proof(signer.id as u64, &signer.keypair.pk)
                .unwrap(),
        );
    }
    // pad the remaining inclusion proofs with same proof
    while signer_pk_inclusion_proofs.len() < n_transactions {
        signer_pk_inclusion_proofs.push(
            tree.generate_proof(signers[0].id as u64, &signers[0].keypair.pk)
                .unwrap(),
        );
    }

    signer_pk_inclusion_proofs
}

pub const TEST_BATCH_SIZE: usize = 5;

#[wasm_bindgen_test]
pub fn test_send_and_receive_transaction() {
    let mut rng = thread_rng();
    let cs = ConstraintSystem::<Fr>::new_ref();
    let pp = poseidon_canonical_config();
    let pp_var = CRHParametersVar::new_constant(cs.clone(), pp.clone()).unwrap();

    let sender = User::new(&mut rng, 42);
    let sender_pk_hash = PublicKeyCRH::evaluate(&pp, sender.keypair.pk).unwrap();
    let receiver = User::new(&mut rng, 43);
    let receiver_pk_hash = PublicKeyCRH::evaluate(&pp, receiver.keypair.pk).unwrap();

    let transaction = make_tx(&sender, &receiver);
    // Vec of [(transaction, index in tx tree)]
    let mut transactions = Vec::from([(transaction, 2)]);
    pad_transaction_vec(&mut transactions, TEST_BATCH_SIZE);
    let transaction_tree = make_tx_tree(&pp, &transactions);
    let transaction_inclusion_proofs =
        get_tx_inclusion_proofs(&transactions, &transaction_tree, TEST_BATCH_SIZE);

    let signer_tree = make_signer_tree(&pp, &Vec::from([sender.clone()]));
    let signers_ids = Vec::from([Some(sender.id)]);
    let signer_pk_inclusion_proofs =
        get_signer_inclusion_proofs(&Vec::from([sender.clone()]), &signer_tree, TEST_BATCH_SIZE);

    let sender_circuit = get_client_circuit::<TEST_BATCH_SIZE>(&pp_var);
    let receiver_circuit = get_client_circuit::<TEST_BATCH_SIZE>(&pp_var);

    let block = Block {
        utxo_tree_root: Fr::ZERO,
        tx_tree_root: transaction_tree.root(),
        signer_tree_root: signer_tree.root(),
        signers: signers_ids,
        height: 1,
        deposits: vec![],
        withdrawals: vec![],
    };

    let sender_aux = UserAux::<_, _, TEST_BATCH_SIZE> {
        transaction_inclusion_proofs,
        signer_pk_inclusion_proofs,
        block: block.clone(),
        transactions,
        pk: sender.keypair.pk,
    };
    let mut receiver_aux = sender_aux.clone();
    receiver_aux.pk = receiver.keypair.pk;

    let sender_aux_var = UserAuxVar::new_witness(cs.clone(), || Ok(sender_aux.clone())).unwrap();
    let receiver_aux_var =
        UserAuxVar::new_witness(cs.clone(), || Ok(receiver_aux.clone())).unwrap();

    let sender_state = Vec::from([
        Fr::from(100),
        Fr::ZERO,
        sender_pk_hash,
        Fr::ZERO,
        Fr::ZERO,
        Fr::ZERO,
        Fr::ZERO,
    ]);
    let sender_state_var = get_state_as_var(cs.clone(), sender_state.clone());
    let receiver_state = Vec::from([
        Fr::from(100),
        Fr::ZERO,
        receiver_pk_hash,
        Fr::ZERO,
        Fr::ZERO,
        Fr::ZERO,
        Fr::ZERO,
    ]);
    let receiver_state_var = get_state_as_var(cs.clone(), receiver_state.clone());

    let updated_sender_state = sender_circuit
        .update_balance(cs.clone(), sender_state_var, sender_aux_var)
        .unwrap();
    assert!(cs.is_satisfied().unwrap());
    console_log!(
        "batchsize: {}, n_constraints sender circuit: {}",
        TEST_BATCH_SIZE,
        cs.num_constraints()
    );

    let expected_block_hash = BlockCRH::evaluate(&pp, block.clone()).unwrap();

    // Check sender updates
    assert_eq!(updated_sender_state[0].value().unwrap(), Fr::ZERO); // balance
    assert_eq!(updated_sender_state[1].value().unwrap(), Fr::ONE); // nonce
    assert_ne!(updated_sender_state[3].value().unwrap(), sender_state[3]); // acc is updated
    assert_eq!(
        updated_sender_state[4].value().unwrap(),
        expected_block_hash
    );
    assert_eq!(updated_sender_state[5].value().unwrap(), Fr::ONE); // prev block number
    assert_eq!(updated_sender_state[6].value().unwrap(), Fr::from(2)); // prev processed tx index

    // Check receiver updates
    let updated_receiver_state = receiver_circuit
        .update_balance(cs.clone(), receiver_state_var, receiver_aux_var)
        .unwrap();

    assert_eq!(updated_receiver_state[0].value().unwrap(), Fr::from(200)); // balance
    assert_eq!(updated_receiver_state[1].value().unwrap(), Fr::ZERO); // nonce is not increased
                                                                      // when receiving
    assert_ne!(
        updated_receiver_state[3].value().unwrap(),
        receiver_state[3]
    ); // acc is updated
    assert_eq!(
        updated_receiver_state[4].value().unwrap(),
        expected_block_hash
    );
    assert_eq!(updated_receiver_state[5].value().unwrap(), Fr::ONE); // prev block number
    assert_eq!(updated_receiver_state[6].value().unwrap(), Fr::from(2)); // prev processed tx index
}

#[wasm_bindgen_test]
pub fn test_lower_block_number() {
    const TEST_BATCH_SIZE: usize = 2;
    let mut rng = thread_rng();
    let cs = ConstraintSystem::<Fr>::new_ref();
    let pp = poseidon_canonical_config();
    let pp_var = CRHParametersVar::new_constant(cs.clone(), pp.clone()).unwrap();

    let sender = User::new(&mut rng, 42);
    let receiver = User::new(&mut rng, 43);

    let sender_pk_hash = PublicKeyCRH::evaluate(&pp, sender.keypair.pk).unwrap();

    let transaction = make_tx(&sender, &receiver);
    // Vec of [(transaction, index in tx tree)]
    let mut transactions = Vec::from([(transaction, 2)]);
    pad_transaction_vec(&mut transactions, TEST_BATCH_SIZE);
    let transaction_tree = make_tx_tree(&pp, &transactions);
    let transaction_inclusion_proofs =
        get_tx_inclusion_proofs(&transactions, &transaction_tree, TEST_BATCH_SIZE);

    let signer_tree = make_signer_tree(&pp, &Vec::from([sender.clone()]));
    let signers_ids = Vec::from([Some(sender.id)]);
    let signer_pk_inclusion_proofs =
        get_signer_inclusion_proofs(&Vec::from([sender.clone()]), &signer_tree, TEST_BATCH_SIZE);

    let sender_circuit = get_client_circuit::<TEST_BATCH_SIZE>(&pp_var);

    let block = Block {
        utxo_tree_root: Fr::ZERO,
        tx_tree_root: transaction_tree.root(),
        signer_tree_root: signer_tree.root(),
        signers: signers_ids,
        height: 1, // NOTE: processed block number
        deposits: vec![],
        withdrawals: vec![],
    };

    let sender_aux = UserAux::<_, _, TEST_BATCH_SIZE> {
        transaction_inclusion_proofs,
        signer_pk_inclusion_proofs,
        block: block.clone(),
        transactions,
        pk: sender.keypair.pk,
    };

    let sender_aux_var = UserAuxVar::new_witness(cs.clone(), || Ok(sender_aux.clone())).unwrap();

    let sender_state = Vec::from([
        Fr::from(1000),
        Fr::ZERO,
        sender_pk_hash,
        Fr::ZERO,
        Fr::ZERO,
        Fr::from(10), // NOTE: prev block number will be greater
        Fr::ZERO,
    ]);
    let sender_state_var = get_state_as_var(cs.clone(), sender_state.clone());

    let _ = sender_circuit
        .update_balance(cs.clone(), sender_state_var, sender_aux_var)
        .unwrap();

    assert!(!cs.is_satisfied().unwrap());
}

#[wasm_bindgen_test]
pub fn test_lower_transaction_index() {
    pub const TEST_BATCH_SIZE: usize = 2;
    let mut rng = thread_rng();
    let cs = ConstraintSystem::<Fr>::new_ref();
    let pp = poseidon_canonical_config();
    let pp_var = CRHParametersVar::new_constant(cs.clone(), pp.clone()).unwrap();

    let sender = User::new(&mut rng, 42);
    let receiver = User::new(&mut rng, 43);

    let sender_pk_hash = PublicKeyCRH::evaluate(&pp, sender.keypair.pk).unwrap();

    let transaction_a = make_tx(&sender, &receiver);
    let transaction_b = make_tx(&sender, &receiver);

    // Vec of [(transaction, index in tx tree)]
    // NOTE: a transaction with a higher index precedes a transaction with a lower one
    let mut transactions = Vec::from([(transaction_b, 10), (transaction_a, 2)]);
    pad_transaction_vec(&mut transactions, TEST_BATCH_SIZE);
    let transaction_tree = make_tx_tree(&pp, &transactions);
    let transaction_inclusion_proofs =
        get_tx_inclusion_proofs(&transactions, &transaction_tree, TEST_BATCH_SIZE);

    let signer_tree = make_signer_tree(&pp, &Vec::from([sender.clone()]));
    let signers_ids = Vec::from([Some(sender.id)]);
    let signer_pk_inclusion_proofs =
        get_signer_inclusion_proofs(&Vec::from([sender.clone()]), &signer_tree, TEST_BATCH_SIZE);

    let sender_circuit = get_client_circuit::<TEST_BATCH_SIZE>(&pp_var);

    let block = Block {
        utxo_tree_root: Fr::ZERO,
        tx_tree_root: transaction_tree.root(),
        signer_tree_root: signer_tree.root(),
        signers: signers_ids,
        height: 1,
        deposits: vec![],
        withdrawals: vec![],
    };

    let sender_aux = UserAux::<_, _, TEST_BATCH_SIZE> {
        transaction_inclusion_proofs,
        signer_pk_inclusion_proofs,
        block: block.clone(),
        transactions,
        pk: sender.keypair.pk,
    };

    let sender_aux_var = UserAuxVar::new_witness(cs.clone(), || Ok(sender_aux.clone())).unwrap();

    let sender_state = Vec::from([
        Fr::from(1000),
        Fr::ZERO,
        sender_pk_hash,
        Fr::ZERO,
        Fr::ZERO,
        Fr::ZERO,
        Fr::ZERO,
    ]);
    let sender_state_var = get_state_as_var(cs.clone(), sender_state.clone());

    let _ = sender_circuit
        .update_balance(cs.clone(), sender_state_var, sender_aux_var)
        .unwrap();

    assert!(!cs.is_satisfied().unwrap());
}

#[wasm_bindgen_test]
pub fn test_stricly_lower_transaction_index() {
    pub const TEST_BATCH_SIZE: usize = 4;
    let mut rng = thread_rng();
    let cs = ConstraintSystem::<Fr>::new_ref();
    let pp = poseidon_canonical_config();
    let pp_var = CRHParametersVar::new_constant(cs.clone(), pp.clone()).unwrap();

    let sender = User::new(&mut rng, 42);
    let receiver = User::new(&mut rng, 43);

    let receiver_pk_hash = PublicKeyCRH::evaluate(&pp, receiver.keypair.pk).unwrap();

    let transaction = make_tx(&sender, &receiver);

    // Vec of [(transaction, index in tx tree)]
    // NOTE: a receiver will fail if trying to replay a block with a valid transaction
    let mut transactions = Vec::from([(transaction, 2)]);
    pad_transaction_vec(&mut transactions, TEST_BATCH_SIZE);
    let transaction_tree = make_tx_tree(&pp, &transactions);
    let transaction_inclusion_proofs =
        get_tx_inclusion_proofs(&transactions, &transaction_tree, TEST_BATCH_SIZE);

    let signer_tree = make_signer_tree(&pp, &Vec::from([sender.clone()]));
    let signers_ids = Vec::from([Some(sender.id)]);
    let signer_pk_inclusion_proofs =
        get_signer_inclusion_proofs(&Vec::from([sender.clone()]), &signer_tree, TEST_BATCH_SIZE);

    let receiver_circuit = get_client_circuit::<TEST_BATCH_SIZE>(&pp_var);

    let block = Block {
        utxo_tree_root: Fr::ZERO,
        tx_tree_root: transaction_tree.root(),
        signer_tree_root: signer_tree.root(),
        signers: signers_ids,
        height: 1,
        deposits: vec![],
        withdrawals: vec![],
    };

    let receiver_aux = UserAux::<_, _, TEST_BATCH_SIZE> {
        transaction_inclusion_proofs,
        signer_pk_inclusion_proofs,
        block: block.clone(),
        transactions,
        pk: receiver.keypair.pk,
    };

    let receiver_aux_var =
        UserAuxVar::new_witness(cs.clone(), || Ok(receiver_aux.clone())).unwrap();

    let receiver_state = Vec::from([
        Fr::from(100),
        Fr::ZERO,
        receiver_pk_hash,
        Fr::ZERO,
        Fr::ZERO,
        Fr::ZERO,
        Fr::ZERO,
    ]);
    let receiver_state_var = get_state_as_var(cs.clone(), receiver_state.clone());

    let updated_receiver_state = receiver_circuit
        .update_balance(
            cs.clone(),
            receiver_state_var.clone(),
            receiver_aux_var.clone(),
        )
        .unwrap();

    // NOTE: the first circuit update passes correctly
    assert!(cs.is_satisfied().unwrap());
    assert_eq!(updated_receiver_state[0].value().unwrap(), Fr::from(200)); // balance
    assert_eq!(updated_receiver_state[5].value().unwrap(), Fr::ONE); // prev block number
    assert_eq!(updated_receiver_state[6].value().unwrap(), Fr::from(2)); // prev processed tx index
                                                                         // is updated

    // NOTE: it fails if the receiver tries to replay the block, with the updated receiver state
    let _ = receiver_circuit
        .update_balance(cs.clone(), updated_receiver_state, receiver_aux_var)
        .unwrap();
    assert!(!cs.is_satisfied().unwrap());
}

#[wasm_bindgen_test]
pub fn test_run_fold_steps() {
    let pp = poseidon_canonical_config();
    let mut rng = thread_rng();

    let user = User::new(&mut rng, 42);
    let user_pk_hash = PublicKeyCRH::evaluate(&pp, user.keypair.pk).unwrap();

    let state = Vec::from([
        Fr::from(2000),
        Fr::ZERO,
        user_pk_hash,
        Fr::ZERO,
        Fr::ZERO,
        Fr::ZERO,
        Fr::ZERO,
    ]);

    let f_circuit =
        ClientCircuitPoseidon::<Fr, Projective, GVar, TEST_BATCH_SIZE>::new(pp.clone()).unwrap();

    type N = Nova<
        Projective2,
        Projective,
        ClientCircuitPoseidon<Fr, Projective, GVar, TEST_BATCH_SIZE>,
        Pedersen<Projective2>,
        Pedersen<Projective>,
        false,
    >;

    let nova_preprocess_params = PreprocessorParam::new(pp.clone(), f_circuit.clone());
    let nova_params = N::preprocess(&mut rng, &nova_preprocess_params).unwrap();
    let mut folding_scheme = N::init(&nova_params, f_circuit, state.clone()).unwrap();

    let mut durations = Vec::new();
    // start at 0 since tx idx 0 is reserved for default transactions in tests
    for i in 1..=10 {
        let receiver = User::new(&mut rng, i);
        let transaction = make_tx(&user, &receiver);
        let mut transactions = Vec::from([(transaction, (i) as u64)]);
        pad_transaction_vec(&mut transactions, TEST_BATCH_SIZE);
        let transaction_tree = make_tx_tree(&pp, &transactions);
        let transaction_inclusion_proofs =
            get_tx_inclusion_proofs(&transactions, &transaction_tree, TEST_BATCH_SIZE);

        let signer_tree = make_signer_tree(&pp, &Vec::from([user.clone()]));
        let signers_ids = Vec::from([Some(user.id)]);
        let signer_pk_inclusion_proofs =
            get_signer_inclusion_proofs(&Vec::from([user.clone()]), &signer_tree, TEST_BATCH_SIZE);

        let block = Block {
            utxo_tree_root: Fr::ONE,
            tx_tree_root: transaction_tree.root(),
            signer_tree_root: signer_tree.root(),
            signers: signers_ids,
            height: i as usize,
            deposits: vec![],
            withdrawals: vec![],
        };

        let user_aux = UserAux {
            transaction_inclusion_proofs,
            signer_pk_inclusion_proofs,
            block: block.clone(),
            transactions,
            pk: user.keypair.pk,
        };

        let start = Instant::now();
        folding_scheme.prove_step(&mut rng, user_aux, None).unwrap();
        let elapsed = start.elapsed();

        durations.push(elapsed);
        console_log!("[POSEIDON] folding step {}, took: {:?}", i, elapsed);
    }
    let total: Duration = durations.iter().sum();

    console_log!(
        "[POSEIDON] batch size: {}, Average folding step time: {:?}",
        TEST_BATCH_SIZE,
        total / durations.len() as u32
    );

    let ivc_proof = folding_scheme.ivc_proof();
    N::verify(
        nova_params.1, // Nova's verifier params
        ivc_proof,
    )
    .unwrap();
}

pub fn get_current_allocated_bytes() -> u64 {
    let js_mem = wasm_bindgen::memory();
    let wasm_mem = js_mem.unchecked_into::<WebAssembly::Memory>();
    let buffer = wasm_mem.buffer();
    Uint8Array::new(&buffer).length() as u64
}

// #[wasm_bindgen_test]
// NOTE: for running memory usage tests, we recommend choosing either the sha or the poseidon
// circuit version. Otherwise, wasm will already have allocated memory from the other circuit
// running, which would report inaccurate memory usage numbers.
// TODO: improve this
pub fn test_memory_usage() {
    let pp = poseidon_canonical_config();
    let mut rng = thread_rng();

    let user = User::new(&mut rng, 42);
    let user_pk_hash = PublicKeyCRH::evaluate(&pp, user.keypair.pk).unwrap();

    type N = Nova<
        Projective2,
        Projective,
        ClientCircuitPoseidon<Fr, Projective, GVar, TEST_BATCH_SIZE>,
        Pedersen<Projective2>,
        Pedersen<Projective>,
        false,
    >;

    let f_circuit =
        ClientCircuitPoseidon::<Fr, Projective, GVar, TEST_BATCH_SIZE>::new(pp.clone()).unwrap();

    let nova_preprocess_params = PreprocessorParam::new(pp.clone(), f_circuit.clone());

    let state = Vec::from([
        Fr::from(2000),
        Fr::ZERO,
        user_pk_hash,
        Fr::ZERO,
        Fr::ZERO,
        Fr::ZERO,
        Fr::ZERO,
    ]);

    let signer_tree = make_signer_tree(&pp, &Vec::from([user.clone()]));

    let nova_params = N::preprocess(&mut rng, &nova_preprocess_params).unwrap();

    let mem_length_start = get_current_allocated_bytes();

    // avoid taking preprocessing step into account
    let nova_params = nova_params.clone();
    let mut folding_scheme = N::init(&nova_params, f_circuit, state.clone()).unwrap();

    let i = 42;
    let receiver = User::new(&mut rng, i);
    let transaction = make_tx(&user, &receiver);
    let mut transactions = Vec::from([(transaction, (i) as u64)]);
    pad_transaction_vec(&mut transactions, TEST_BATCH_SIZE);
    let transaction_tree = make_tx_tree(&pp, &transactions);
    let transaction_inclusion_proofs =
        get_tx_inclusion_proofs(&transactions, &transaction_tree, TEST_BATCH_SIZE);

    let signers_ids = Vec::from([Some(user.id)]);
    let signer_pk_inclusion_proofs =
        get_signer_inclusion_proofs(&Vec::from([user.clone()]), &signer_tree, TEST_BATCH_SIZE);

    let block = Block {
        utxo_tree_root: Fr::ONE,
        tx_tree_root: transaction_tree.root(),
        signer_tree_root: signer_tree.root(),
        signers: signers_ids,
        height: i as usize,
        deposits: vec![],
        withdrawals: vec![],
    };

    let user_aux = UserAux {
        transaction_inclusion_proofs,
        signer_pk_inclusion_proofs,
        block: block.clone(),
        transactions,
        pk: user.keypair.pk,
    };

    folding_scheme.prove_step(&mut rng, user_aux, None).unwrap();

    let mem_length_stop = get_current_allocated_bytes();

    console_log!(
        "[POSEIDON] batch size: {}, current mem length (kB): {}",
        TEST_BATCH_SIZE,
        (mem_length_stop - mem_length_start) / 1024
    );

    let ivc_proof = folding_scheme.ivc_proof();
    N::verify(
        nova_params.1, // Nova's verifier params
        ivc_proof,
    )
    .unwrap();
}

#[wasm_bindgen_test]
pub fn test_sha_constraints() {
    const TEST_BATCH_SIZE: usize = 5;
    let mut rng = thread_rng();
    let cs = ConstraintSystem::<Fr>::new_ref();
    let pp = poseidon_canonical_config();
    let pp_var = CRHParametersVar::new_constant(cs.clone(), pp.clone()).unwrap();

    let sender = User::new(&mut rng, 42);
    let sender_pk_hash = PublicKeyCRH::evaluate(&pp, sender.keypair.pk).unwrap();
    let receiver = User::new(&mut rng, 43);

    let transaction = make_tx(&sender, &receiver);
    // Vec of [(transaction, index in tx tree)]
    let mut transactions = Vec::from([(transaction, 2)]);
    pad_transaction_vec(&mut transactions, TEST_BATCH_SIZE);
    let transaction_tree = make_tx_tree(&pp, &transactions);
    let transaction_inclusion_proofs =
        get_tx_inclusion_proofs(&transactions, &transaction_tree, TEST_BATCH_SIZE);

    let signer_tree = make_signer_tree(&pp, &Vec::from([sender.clone()]));
    let signers_ids = Vec::from([Some(sender.id)]);
    let signer_pk_inclusion_proofs =
        get_signer_inclusion_proofs(&Vec::from([sender.clone()]), &signer_tree, TEST_BATCH_SIZE);

    // NOTE: instantiating sha circuit here
    let sender_circuit = get_client_circuit_sha::<TEST_BATCH_SIZE>(cs.clone(), &pp_var);

    let block = Block {
        utxo_tree_root: Fr::ZERO,
        tx_tree_root: transaction_tree.root(),
        signer_tree_root: signer_tree.root(),
        signers: signers_ids,
        height: 1, // NOTE: processed block numberAdd commentMore actions
        deposits: vec![],
        withdrawals: vec![],
    };

    let sender_aux = UserAux::<_, _, TEST_BATCH_SIZE> {
        transaction_inclusion_proofs,
        signer_pk_inclusion_proofs,
        block: block.clone(),
        transactions,
        pk: sender.keypair.pk,
    };
    let mut receiver_aux = sender_aux.clone();
    receiver_aux.pk = receiver.keypair.pk;

    let sender_aux_var = UserAuxVar::new_witness(cs.clone(), || Ok(sender_aux.clone())).unwrap();

    let sender_state = Vec::from([
        Fr::from(100),
        Fr::ZERO,
        sender_pk_hash,
        Fr::ZERO,
        Fr::ZERO,
        Fr::ZERO,
        Fr::ZERO,
    ]);
    let sender_state_var = get_state_as_var(cs.clone(), sender_state.clone());
    let _ = sender_circuit
        .update_balance(cs.clone(), sender_state_var, sender_aux_var)
        .unwrap();
    assert!(cs.is_satisfied().unwrap());
    console_log!(
        "[POSEIDON] batch size: {}, n_constraints sender circuit: {}",
        TEST_BATCH_SIZE,
        cs.num_constraints()
    );
}

#[wasm_bindgen_test]
pub fn test_run_fold_steps_sha() {
    const TEST_BATCH_SIZE: usize = 5;
    let pp = poseidon_canonical_config();
    let mut rng = thread_rng();

    let user = User::new(&mut rng, 42);
    let user_pk_hash = PublicKeyCRH::evaluate(&pp, user.keypair.pk).unwrap();

    let state = Vec::from([
        Fr::from(2000),
        Fr::ZERO,
        user_pk_hash,
        Fr::ZERO,
        Fr::ZERO,
        Fr::ZERO,
        Fr::ZERO,
    ]);

    // NOTE: instantiating sha circuit here
    let f_circuit =
        ClientCircuitSha::<Fr, Projective, GVar, TEST_BATCH_SIZE>::new(pp.clone()).unwrap();

    type N = Nova<
        Projective2,
        Projective,
        ClientCircuitSha<Fr, Projective, GVar, TEST_BATCH_SIZE>,
        Pedersen<Projective2>,
        Pedersen<Projective>,
        false,
    >;

    let nova_preprocess_params = PreprocessorParam::new(pp.clone(), f_circuit.clone());
    let nova_params = N::preprocess(&mut rng, &nova_preprocess_params).unwrap();
    let mut folding_scheme = N::init(&nova_params, f_circuit, state.clone()).unwrap();

    let mut durations = Vec::new();
    // start at 0 since tx idx 0 is reserved for default transactions in tests
    for i in 1..=10 {
        let receiver = User::new(&mut rng, i);
        let transaction = make_tx(&user, &receiver);
        let mut transactions = Vec::from([(transaction, (i) as u64)]);
        pad_transaction_vec(&mut transactions, TEST_BATCH_SIZE);
        let transaction_tree = make_tx_tree(&pp, &transactions);
        let transaction_inclusion_proofs =
            get_tx_inclusion_proofs(&transactions, &transaction_tree, TEST_BATCH_SIZE);

        let signer_tree = make_signer_tree(&pp, &Vec::from([user.clone()]));
        let signers_ids = Vec::from([Some(user.id)]);
        let signer_pk_inclusion_proofs =
            get_signer_inclusion_proofs(&Vec::from([user.clone()]), &signer_tree, TEST_BATCH_SIZE);

        let block = Block {
            utxo_tree_root: Fr::ONE,
            tx_tree_root: transaction_tree.root(),
            signer_tree_root: signer_tree.root(),
            signers: signers_ids,
            height: 1, // NOTE: processed block numberAdd commentMore actions
            deposits: vec![],
            withdrawals: vec![],
        };

        let user_aux = UserAux {
            transaction_inclusion_proofs,
            signer_pk_inclusion_proofs,
            block: block.clone(),
            transactions,
            pk: user.keypair.pk,
        };

        let start = Instant::now();
        folding_scheme.prove_step(&mut rng, user_aux, None).unwrap();
        let elapsed = start.elapsed();

        durations.push(elapsed);
        console_log!("[SHA] folding step {}, took: {:?}", i, elapsed);
    }
    let total: Duration = durations.iter().sum();

    console_log!(
        "[SHA] Batch size: {}, Average folding step time: {:?}",
        TEST_BATCH_SIZE,
        total / durations.len() as u32
    );

    let ivc_proof = folding_scheme.ivc_proof();
    N::verify(
        nova_params.1, // Nova's verifier params
        ivc_proof,
    )
    .unwrap();
}

#[wasm_bindgen_test]
pub fn test_memory_usage_sha() {
    const TEST_BATCH_SIZE: usize = 5;
    let pp = poseidon_canonical_config();
    let mut rng = thread_rng();

    let user = User::new(&mut rng, 42);
    let user_pk_hash = PublicKeyCRH::evaluate(&pp, user.keypair.pk).unwrap();

    // NOTE: instantiating sha circuit here
    let f_circuit =
        ClientCircuitSha::<Fr, Projective, GVar, TEST_BATCH_SIZE>::new(pp.clone()).unwrap();

    type N = Nova<
        Projective2,
        Projective,
        ClientCircuitSha<Fr, Projective, GVar, TEST_BATCH_SIZE>,
        Pedersen<Projective2>,
        Pedersen<Projective>,
        false,
    >;

    let nova_preprocess_params = PreprocessorParam::new(pp.clone(), f_circuit.clone());

    let state = Vec::from([
        Fr::from(2000),
        Fr::ZERO,
        user_pk_hash,
        Fr::ZERO,
        Fr::ZERO,
        Fr::ZERO,
        Fr::ZERO,
    ]);

    let signer_tree = make_signer_tree(&pp, &Vec::from([user.clone()]));

    let nova_params = N::preprocess(&mut rng, &nova_preprocess_params).unwrap();

    let mem_length_start = get_current_allocated_bytes();

    // avoid taking preprocessing step into account
    let nova_params = nova_params.clone();
    let mut folding_scheme = N::init(&nova_params, f_circuit, state.clone()).unwrap();

    let i = 42;
    let receiver = User::new(&mut rng, i);
    let transaction = make_tx(&user, &receiver);
    let mut transactions = Vec::from([(transaction, (i) as u64)]);
    pad_transaction_vec(&mut transactions, TEST_BATCH_SIZE);
    let transaction_tree = make_tx_tree(&pp, &transactions);
    let transaction_inclusion_proofs =
        get_tx_inclusion_proofs(&transactions, &transaction_tree, TEST_BATCH_SIZE);

    let signers_ids = Vec::from([Some(user.id)]);
    let signer_pk_inclusion_proofs =
        get_signer_inclusion_proofs(&Vec::from([user.clone()]), &signer_tree, TEST_BATCH_SIZE);

    let block = Block {
        utxo_tree_root: Fr::ONE,
        tx_tree_root: transaction_tree.root(),
        signer_tree_root: signer_tree.root(),
        signers: signers_ids,
        height: 1, // NOTE: processed block numberAdd commentMore actions
        deposits: vec![],
        withdrawals: vec![],
    };

    let user_aux = UserAux {
        transaction_inclusion_proofs,
        signer_pk_inclusion_proofs,
        block: block.clone(),
        transactions,
        pk: user.keypair.pk,
    };

    folding_scheme.prove_step(&mut rng, user_aux, None).unwrap();

    let mem_length_stop = get_current_allocated_bytes();

    console_log!(
        "[SHA] batch size: {}, current mem length (kB): {}",
        TEST_BATCH_SIZE,
        (mem_length_stop - mem_length_start) / 1024
    );

    let ivc_proof = folding_scheme.ivc_proof();
    N::verify(
        nova_params.1, // Nova's verifier params
        ivc_proof,
    )
    .unwrap();
}
