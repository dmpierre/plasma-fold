use std::marker::PhantomData;

use super::{keypair::PublicKey, utxo::UTXO, TX_IO_SIZE};
use crate::{
    errors::TransactionError,
    primitives::{
        crh::TransactionCRH,
        sparsemt::{MerkleSparseTree, SparseConfig},
    },
    TX_TREE_HEIGHT,
};
use ark_crypto_primitives::{
    crh::{poseidon::TwoToOneCRH, CRHScheme},
    merkle_tree::{Config, IdentityDigestConverter},
    sponge::{poseidon::PoseidonConfig, Absorb},
    Error,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;

pub mod constraints;

#[derive(Clone, Debug)]
pub struct Transaction<C: CurveGroup> {
    pub inputs: [UTXO<C>; TX_IO_SIZE],
    pub outputs: [UTXO<C>; TX_IO_SIZE],
}

impl<C: CurveGroup> Default for Transaction<C> {
    fn default() -> Self {
        Transaction {
            inputs: [UTXO::dummy(); TX_IO_SIZE],
            outputs: [UTXO::dummy(); TX_IO_SIZE],
        }
    }
}

impl<F: PrimeField + Absorb, C: CurveGroup<BaseField = F>> Transaction<C> {
    pub fn get_hash(&self, parameters: &PoseidonConfig<F>) -> Result<F, Error> {
        TransactionCRH::evaluate(parameters, self)
    }
}

impl<F: PrimeField, C: CurveGroup<BaseField = F>> From<&Transaction<C>> for Vec<F> {
    fn from(val: &Transaction<C>) -> Self {
        let mut arr = Vec::new();
        for utxo in val.inputs.iter().chain(&val.outputs) {
            arr.push(F::from(utxo.amount));
            arr.push(F::from(utxo.is_dummy));
            let point = utxo.pk.key.into_affine();
            let (x, y, iszero) = if point.is_zero() {
                (F::ZERO, F::ZERO, F::ONE)
            } else {
                (point.x().unwrap(), point.y().unwrap(), F::ZERO)
            };
            arr.push(x);
            arr.push(y);
            arr.push(iszero);
        }
        arr
    }
}

impl<F: PrimeField, C: CurveGroup> From<Transaction<C>> for Vec<F> {
    fn from(val: Transaction<C>) -> Self {
        let arr = val
            .inputs
            .iter()
            .chain(&val.outputs)
            .flat_map(|utxo| [F::from(utxo.amount), F::from(utxo.is_dummy)])
            .collect::<Vec<_>>();
        arr
    }
}

impl<C: CurveGroup> AsRef<Transaction<C>> for Transaction<C> {
    fn as_ref(&self) -> &Transaction<C> {
        self
    }
}

impl<C: CurveGroup> Transaction<C> {
    pub fn is_valid(&self, sender: Option<PublicKey<C>>) -> Result<(), TransactionError> {
        let sender = sender.unwrap_or(self.inputs[0].pk);
        if self
            .inputs
            .iter()
            .filter(|utxo| !utxo.is_dummy)
            .any(|utxo| utxo.pk.key != sender.key)
        {
            return Err(TransactionError::InvalidPublicKey);
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
            return Err(TransactionError::InvalidAmounts);
        }
        Ok(())
    }
}

pub type TransactionTree<P> = MerkleSparseTree<P>;

#[derive(Clone, Debug)]
pub struct TransactionTreeConfig<C: CurveGroup> {
    _c: PhantomData<C>,
}

impl<F: PrimeField + Absorb, C: CurveGroup<BaseField = F>> Config for TransactionTreeConfig<C> {
    type Leaf = Transaction<C>;
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = TransactionCRH<F, C>;
    type TwoToOneHash = TwoToOneCRH<F>;
}

impl<F: PrimeField + Absorb, C: CurveGroup<BaseField = F>> SparseConfig
    for TransactionTreeConfig<C>
{
    const HEIGHT: u64 = TX_TREE_HEIGHT;
}

#[cfg(test)]
pub mod tests {

    use std::collections::BTreeMap;

    use super::{Transaction, TransactionTreeConfig};
    use crate::{
        datastructures::{
            keypair::{
                constraints::{PublicKeyVar, SignatureVar},
                PublicKey,
            },
            transaction::{
                constraints::{TransactionTreeConfigGadget, TransactionVar},
                TransactionTree,
            },
            user::User,
            utxo::UTXO,
            TX_IO_SIZE,
        },
        primitives::{
            schnorr::SchnorrGadget,
            sparsemt::constraints::{MerkleSparseTreePathVar, MerkleSparseTreeTwoPathsVar},
        },
    };
    use ark_bn254::Fr;
    use ark_crypto_primitives::crh::poseidon::constraints::CRHParametersVar;
    use ark_grumpkin::constraints::GVar;
    use ark_grumpkin::Projective;
    use ark_r1cs_std::{
        alloc::AllocVar,
        fields::{fp::FpVar, FieldVar},
    };
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::rand::thread_rng;
    use folding_schemes::transcript::poseidon::poseidon_canonical_config;
    const W: usize = 32;

    #[test]
    pub fn test_transaction_tree() {
        let tx_tree_height = 10;
        let n_transactions = 2_usize.pow(tx_tree_height);
        let pp = poseidon_canonical_config();

        // Build tx tree
        let transactions = (0..n_transactions)
            .map(|_| Transaction::default())
            .collect::<Vec<Transaction<Projective>>>();
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

        let tx_path = tx_tree.generate_proof(0, &transactions[0]).unwrap();

        // Tx inclusion circuit
        let cs = ConstraintSystem::<Fr>::new_ref();
        let pp_var = CRHParametersVar::new_constant(cs.clone(), &pp).unwrap();

        // Initialize root, leaf and path as vars
        let tx_tree_root_var = FpVar::new_witness(cs.clone(), || Ok(tx_tree.root())).unwrap();
        let tx_leaf_var = TransactionVar::<Fr, Projective, GVar>::new_witness(cs.clone(), || {
            Ok(transactions[0].clone())
        })
        .unwrap();

        let tx_path_var = MerkleSparseTreePathVar::<
            _,
            _,
            TransactionTreeConfigGadget<Fr, Projective, GVar>,
        >::new_witness(cs.clone(), || Ok(tx_path))
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
        let tx = Transaction::<Projective>::default();
        let tx_signature = user
            .sign(&pp, &Into::<Vec<_>>::into(&tx), &mut rng)
            .unwrap();

        // alloc tx, h(tx), user.pubkey and sign(tx)
        let tx_var = TransactionVar::<_, _, GVar>::new_witness(cs.clone(), || Ok(tx)).unwrap();
        let pk_var =
            PublicKeyVar::<Projective, GVar>::new_witness(cs.clone(), || Ok(user.keypair.pk))
                .unwrap();
        let signature_var = SignatureVar::new_witness(cs.clone(), || Ok(tx_signature)).unwrap();

        // check sign(tx)
        SchnorrGadget::verify::<W, _, _>(
            &pp_var,
            &pk_var.key,
            &TryInto::<Vec<_>>::try_into(&tx_var).unwrap(),
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
        let tx_tree_height = 4_usize;
        let n_transactions = 1 << (tx_tree_height - 1);
        let pp = poseidon_canonical_config();
        let empty_leaves = (0..n_transactions)
            .map(|_| Transaction::default())
            .collect::<Vec<Transaction<Projective>>>();

        // can not use blank, at least for now, since it requires LeafDigest::default();
        let mut tx_tree = TransactionTree::<TransactionTreeConfig<Projective>>::new(
            &pp,
            &pp,
            &BTreeMap::from_iter(
                empty_leaves
                    .iter()
                    .enumerate()
                    .map(|(i, tx)| (i as u64, tx.clone())),
            ),
        )
        .unwrap();

        // initialize transactions received by the aggregator
        let transactions = (0..n_transactions)
            .map(|_i| Transaction {
                inputs: [UTXO::new(PublicKey::default(), 10); TX_IO_SIZE],
                outputs: [UTXO::new(PublicKey::default(), 10); TX_IO_SIZE],
            })
            .collect::<Vec<Transaction<Projective>>>();

        // build the tree incrementally and store intermediary roots
        let mut update_proofs = Vec::with_capacity(transactions.len());
        for (idx, tx) in transactions.iter().enumerate() {
            let prev_root = tx_tree.root();
            let update_proof = tx_tree.update_and_prove(idx as u64, tx).unwrap();
            let new_root = tx_tree.root();
            update_proof
                .verify(
                    &pp,
                    &pp,
                    &prev_root,
                    &new_root,
                    &Transaction::default(),
                    tx,
                    idx as u64,
                )
                .unwrap();
            update_proofs.push((update_proof, prev_root, new_root, tx, idx));
        }

        // tx tree update circuit
        let cs = ConstraintSystem::<Fr>::new_ref();
        let pp_var = CRHParametersVar::new_constant(cs.clone(), &pp).unwrap();
        let n_update_proofs = update_proofs.len();
        for (tx_update, prev_root, new_root, tx, idx) in update_proofs {
            let update_var = MerkleSparseTreeTwoPathsVar::<
                _,
                _,
                TransactionTreeConfigGadget<Fr, Projective, GVar>,
            >::new_witness(cs.clone(), || Ok(tx_update))
            .unwrap();
            let prev_root_var = FpVar::new_witness(cs.clone(), || Ok(prev_root)).unwrap();
            let new_root_var = FpVar::new_witness(cs.clone(), || Ok(new_root)).unwrap();
            let tx_var = TransactionVar::new_witness(cs.clone(), || Ok(tx)).unwrap();
            update_var
                .check_update(
                    &pp_var,
                    &pp_var,
                    &prev_root_var,
                    &new_root_var,
                    &TransactionVar::new_constant(cs.clone(), Transaction::default()).unwrap(),
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
