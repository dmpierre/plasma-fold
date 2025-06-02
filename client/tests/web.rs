use ark_bn254::Fr;
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
use client::{
    circuits::{UserAux, UserAuxVar, UserCircuit},
    N_TX_PER_FOLD_STEP,
};
use folding_schemes::{folding::traits::Dummy, transcript::poseidon::poseidon_canonical_config};
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
use wasm_bindgen_test::*;

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
        nonce: sender.nonce,
    }
}

pub fn pad_transaction_vec(transaction_vec: &mut Vec<(Transaction<Projective>, u64)>) {
    while transaction_vec.len() < N_TX_PER_FOLD_STEP {
        transaction_vec.push((Transaction::dummy(()), 0))
    }
}

pub fn get_client_circuit(
    pp_var: &CRHParametersVar<Fr>,
) -> UserCircuit<
    Fr,
    Projective,
    GVar,
    TwoToOneCRH<Fr>,
    TwoToOneCRHGadget<Fr>,
    PoseidonAccumulatorVar<Fr>,
> {
    UserCircuit::<
        Fr,
        Projective,
        GVar,
        TwoToOneCRH<Fr>,
        TwoToOneCRHGadget<Fr>,
        PoseidonAccumulatorVar<Fr>,
    >::new(pp_var.clone(), pp_var.clone())
}

// make transaction tree from a specified vector of transactions, along with their indexes in the
// transaction tree
pub fn make_tx_tree(
    pp: &PoseidonConfig<Fr>,
    transactions: &Vec<(Transaction<Projective>, u64)>,
) -> TransactionTree<TransactionTreeConfig<Projective>> {
    let leaves = BTreeMap::from_iter(transactions.into_iter().map(|(tx, i)| (*i, tx.clone())));
    TransactionTree::new(pp, pp, &leaves).unwrap()
}

// build vector consisting in transaction inclusion proofs
pub fn get_tx_inclusion_proofs(
    transactions: &Vec<(Transaction<Projective>, u64)>,
    transaction_tree: &TransactionTree<TransactionTreeConfig<Projective>>,
) -> Vec<MerkleSparseTreePath<TransactionTreeConfig<Projective>>> {
    let mut tx_inclusion_proofs = Vec::new();
    for (tx, idx) in transactions {
        tx_inclusion_proofs.push(transaction_tree.generate_proof(*idx, tx).unwrap());
    }
    while tx_inclusion_proofs.len() < N_TX_PER_FOLD_STEP {
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
) -> Vec<MerkleSparseTreePath<SignerTreeConfig<Projective>>> {
    let mut signer_pk_inclusion_proofs = Vec::new();
    for signer in signers {
        signer_pk_inclusion_proofs.push(
            tree.generate_proof(signer.id as u64, &signer.keypair.pk)
                .unwrap(),
        );
    }
    // pad the remaining inclusion proofs with same proof
    while signer_pk_inclusion_proofs.len() < N_TX_PER_FOLD_STEP {
        signer_pk_inclusion_proofs.push(
            tree.generate_proof(signers[0].id as u64, &signers[0].keypair.pk)
                .unwrap(),
        );
    }

    signer_pk_inclusion_proofs
}

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
    pad_transaction_vec(&mut transactions);
    let transaction_tree = make_tx_tree(&pp, &transactions);
    let transaction_inclusion_proofs = get_tx_inclusion_proofs(&transactions, &transaction_tree);

    let signer_tree = make_signer_tree(&pp, &Vec::from([sender.clone()]));
    let signers_ids = Vec::from([Some(sender.id)]);
    let signer_pk_inclusion_proofs =
        get_signer_inclusion_proofs(&Vec::from([sender.clone()]), &signer_tree);

    let sender_circuit = get_client_circuit(&pp_var);
    let receiver_circuit = get_client_circuit(&pp_var);

    let block = Block {
        utxo_tree_root: Fr::ZERO,
        tx_tree_root: transaction_tree.root(),
        signer_tree_root: signer_tree.root(),
        signers: signers_ids,
        number: Fr::ONE,
    };

    let sender_aux = UserAux {
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
    console_log!("n_constraints sender circuit: {}", cs.num_constraints());

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
pub fn test_lower_block_number() {}

#[wasm_bindgen_test]
pub fn test_lower_transaction_index() {}
