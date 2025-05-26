use std::marker::PhantomData;

use super::{noncemap::Nonce, user::UserId, utxo::UTXO, TX_IO_SIZE};
use crate::primitives::{
    crh::TransactionCRH,
    sparsemt::{MerkleSparseTree, SparseConfig},
};
use ark_crypto_primitives::{
    crh::{poseidon::TwoToOneCRH, CRHScheme},
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    sponge::{poseidon::PoseidonConfig, Absorb},
    Error,
};
use ark_ff::PrimeField;

pub mod constraints;

#[derive(Clone, Debug, Copy, PartialEq)]
pub struct Transaction {
    pub inputs: [UTXO; TX_IO_SIZE],
    pub outputs: [UTXO; TX_IO_SIZE],
    pub nonce: Nonce,
}

impl Default for Transaction {
    fn default() -> Self {
        Transaction {
            inputs: [UTXO::dummy(); TX_IO_SIZE],
            outputs: [UTXO::dummy(); TX_IO_SIZE],
            nonce: Nonce(0),
        }
    }
}

impl Transaction {
    pub fn get_hash<F: PrimeField + Absorb>(
        &self,
        parameters: &PoseidonConfig<F>,
    ) -> Result<F, Error> {
        Ok(TransactionCRH::evaluate(parameters, self)?)
    }
}

impl<F: PrimeField> Into<Vec<F>> for &Transaction {
    fn into(self) -> Vec<F> {
        let mut arr = self
            .inputs
            .iter()
            .chain(&self.outputs)
            .flat_map(|utxo| [F::from(utxo.amount), F::from(utxo.id)])
            .collect::<Vec<_>>();
        arr.push(F::from(self.nonce.0));
        arr
    }
}

impl<F: PrimeField> Into<Vec<F>> for Transaction {
    fn into(self) -> Vec<F> {
        let mut arr = self
            .inputs
            .iter()
            .chain(&self.outputs)
            .flat_map(|utxo| [F::from(utxo.amount), F::from(utxo.id)])
            .collect::<Vec<_>>();
        arr.push(F::from(self.nonce.0));
        arr
    }
}

impl AsRef<Transaction> for Transaction {
    fn as_ref(&self) -> &Transaction {
        &self
    }
}

impl Transaction {
    pub fn is_valid(&self, sender: Option<UserId>, nonce: Option<Nonce>) -> bool {
        let sender = sender.unwrap_or(self.inputs[0].id);
        if self
            .inputs
            .iter()
            .filter(|utxo| !utxo.is_dummy)
            .any(|utxo| utxo.id != sender)
        {
            return false;
        }
        if self
            .inputs
            .iter()
            .filter(|utxo| !utxo.is_dummy)
            .map(|utxo| utxo.amount)
            .sum::<u64>()
            != self
                .outputs
                .iter()
                .filter(|utxo| !utxo.is_dummy)
                .map(|utxo| utxo.amount)
                .sum::<u64>()
        {
            return false;
        }
        if nonce.is_some() && nonce != Some(self.nonce) {
            return false;
        }
        true
    }
}

pub type TransactionTree<P> = MerkleSparseTree<P>;

pub struct TransactionTreeConfig<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> Config for TransactionTreeConfig<F> {
    type Leaf = Transaction;
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = TransactionCRH<F>;
    type TwoToOneHash = TwoToOneCRH<F>;
}

impl<F: PrimeField + Absorb> SparseConfig for TransactionTreeConfig<F> {
    const HEIGHT: u64 = 13;
}

#[cfg(test)]
pub mod tests {

    use std::collections::BTreeMap;

    use super::{Transaction, TransactionTreeConfig};
    use crate::{
        circuits::gadgets::{TreeGadgets, TreeUpdateProof, TreeUpdateProofVar},
        datastructures::{
            keypair::constraints::{PublicKeyVar, SignatureVar},
            noncemap::Nonce,
            transaction::{
                constraints::{TransactionTreeConfigGadget, TransactionVar},
                TransactionTree,
            },
            user::User,
            utxo::UTXO,
            TX_IO_SIZE,
        },
        primitives::{
            crh::constraints::TransactionVarCRH,
            schnorr::SchnorrGadget,
            sparsemt::constraints::{MerkleSparseTreePathVar, MerkleSparseTreeTwoPathsVar},
        },
    };
    use ark_bn254::Fr;
    use ark_crypto_primitives::{
        crh::{poseidon::constraints::CRHParametersVar, CRHSchemeGadget},
        merkle_tree::constraints::PathVar,
    };
    use ark_grumpkin::{constraints::GVar, Projective};
    use ark_r1cs_std::{
        alloc::AllocVar,
        fields::{fp::FpVar, FieldVar},
        R1CSVar,
    };
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::rand::thread_rng;
    use folding_schemes::transcript::poseidon::poseidon_canonical_config;

    const W: usize = 32;

    #[test]
    pub fn test_transaction_tree() {
        let tx_tree_height = 10;
        let n_transactions = (2 as usize).pow(tx_tree_height);
        let pp = poseidon_canonical_config();

        // Build tx tree
        let transactions = (0..n_transactions)
            .map(|_| Transaction::default())
            .collect::<Vec<Transaction>>();
        let tx_tree = TransactionTree::<TransactionTreeConfig<Fr>>::new(
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

        let tx_path = tx_tree.generate_proof(0, &transactions[0]).unwrap();

        // Tx inclusion circuit
        let cs = ConstraintSystem::<Fr>::new_ref();
        let pp_var = CRHParametersVar::new_constant(cs.clone(), &pp).unwrap();

        // Initialize root, leaf and path as vars
        let tx_tree_root_var = FpVar::new_witness(cs.clone(), || Ok(tx_tree.root())).unwrap();
        let tx_leaf_var = TransactionVar::new_witness(cs.clone(), || Ok(transactions[0])).unwrap();
        let tx_path_var =
            MerkleSparseTreePathVar::<_, _, TransactionTreeConfigGadget<_>>::new_witness(
                cs.clone(),
                || Ok(tx_path),
            )
            .unwrap();

        // Verify membership
        tx_path_var
            .check_membership_with_index(
                &pp_var,
                &pp_var,
                &tx_tree_root_var,
                &tx_leaf_var,
                &FpVar::zero(),
            )
            .unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    pub fn test_tx_signature_verification_circuit() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut rng = &mut thread_rng();
        let pp = poseidon_canonical_config::<Fr>();
        let pp_var = CRHParametersVar::new_constant(cs.clone(), &pp).unwrap();

        // initialize user, tx, h(tx) and sign(tx)
        let user = User::<Projective>::new(rng, 1);
        let tx = Transaction::default();
        let tx_hash = tx.get_hash(&pp).unwrap();
        let tx_signature = user.sign(&pp, tx_hash, &mut rng).unwrap();

        // alloc tx, h(tx), user.pubkey and sign(tx)
        let tx_var = TransactionVar::new_witness(cs.clone(), || Ok(tx)).unwrap();
        let tx_hash_var = TransactionVarCRH::evaluate(&pp_var, &tx_var).unwrap();
        let pk_var =
            PublicKeyVar::<Projective, GVar>::new_witness(cs.clone(), || Ok(user.keypair.pk))
                .unwrap();
        let signature_var = SignatureVar::new_witness(cs.clone(), || Ok(tx_signature)).unwrap();

        // check sign(tx)
        let res = SchnorrGadget::verify::<W, _, _>(
            &pp_var,
            &pk_var.key,
            tx_hash_var,
            (signature_var.s, signature_var.e),
        )
        .unwrap();

        println!(
            "Tx hash + signature n_constraints: {}",
            cs.num_constraints()
        );
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    pub fn test_initialize_blank_tx_tree_and_update() {
        let tx_tree_height = 4 as usize;
        let n_transactions = 1 << tx_tree_height - 1;
        let pp = poseidon_canonical_config();
        let empty_leaves = (0..n_transactions)
            .map(|_| Transaction::default())
            .collect::<Vec<Transaction>>();

        // can not use blank, at least for now, since it requires LeafDigest::default();
        let mut tx_tree = TransactionTree::<TransactionTreeConfig<Fr>>::new(
            &pp,
            &pp,
            &&BTreeMap::from_iter(
                empty_leaves
                    .iter()
                    .enumerate()
                    .map(|(i, tx)| (i as u64, tx.clone())),
            ),
        )
        .unwrap();

        // initialize transactions received by the aggregator
        let transactions = (0..n_transactions)
            .map(|i| Transaction {
                inputs: [UTXO::new(0, 10); TX_IO_SIZE],
                outputs: [UTXO::new(0, 10); TX_IO_SIZE],
                nonce: Nonce(i),
            })
            .collect::<Vec<Transaction>>();

        // build the tree incrementally and store intermediary roots
        let mut update_proofs = Vec::with_capacity(transactions.len());
        for (idx, tx) in transactions.iter().enumerate() {
            let prev_root = tx_tree.root();
            let update_proof = tx_tree.update_and_prove(idx as u64, tx).unwrap();
            let new_root = tx_tree.root();
            update_proof
                .verify(&pp, &pp, &prev_root, &new_root, &tx, idx as u64)
                .unwrap();
            update_proofs.push((update_proof, prev_root, new_root, tx, idx));
        }

        // tx tree update circuit
        let cs = ConstraintSystem::<Fr>::new_ref();
        let pp_var = CRHParametersVar::new_constant(cs.clone(), &pp).unwrap();
        let n_update_proofs = update_proofs.len();
        for (tx_update, prev_root, new_root, tx, idx) in update_proofs {
            let update_var =
                MerkleSparseTreeTwoPathsVar::<_, _, TransactionTreeConfigGadget<_>>::new_witness(
                    cs.clone(),
                    || Ok(tx_update),
                )
                .unwrap();
            let prev_root_var = FpVar::new_witness(cs.clone(), || Ok(prev_root)).unwrap();
            let new_root_var = FpVar::new_witness(cs.clone(), || Ok(new_root)).unwrap();
            let tx_var = TransactionVar::new_witness(cs.clone(), || Ok(tx)).unwrap();
            let _ = update_var
                .check_update(
                    &pp_var,
                    &pp_var,
                    &prev_root_var,
                    &new_root_var,
                    &tx_var,
                    &FpVar::constant(Fr::from(idx as u64)),
                )
                .unwrap();
        }

        assert!(cs.is_satisfied().unwrap());
        println!(
            "n update_proofs: {n_update_proofs}, avg constraints per update proof: {}",
            cs.num_constraints() / n_update_proofs
        );
    }
}
