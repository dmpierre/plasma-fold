use std::marker::PhantomData;

use super::{noncemap::Nonce, user::UserId, utxo::UTXO, TX_IO_SIZE};
use crate::primitives::crh::TransactionCRH;
use ark_crypto_primitives::{
    crh::{poseidon::TwoToOneCRH, CRHScheme},
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    sponge::{poseidon::PoseidonConfig, Absorb},
    Error,
};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;

pub mod constraints;

#[derive(Clone, Debug, Copy, Default, CanonicalSerialize)]
pub struct Transaction {
    inputs: [UTXO; TX_IO_SIZE],
    outputs: [UTXO; TX_IO_SIZE],
    nonce: Nonce,
}

impl Transaction {
    pub fn get_hash<F: PrimeField + Absorb>(
        &self,
        parameters: &PoseidonConfig<F>,
    ) -> Result<F, Error> {
        Ok(TransactionCRH::evaluate(parameters, self)?)
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
        arr.push(F::from(self.nonce));
        arr
    }
}

impl AsRef<Transaction> for Transaction {
    fn as_ref(&self) -> &Transaction {
        &self
    }
}

impl Absorb for Transaction {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        for utxo in self.inputs.iter().chain(&self.outputs) {
            dest.extend(utxo.amount.to_le_bytes());
            dest.extend(utxo.id.to_le_bytes());
        }
        dest.extend(self.nonce.to_le_bytes());
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        let tx_vec = Into::<Vec<F>>::into(*self);
        dest.extend(tx_vec)
    }
}

impl Transaction {
    pub fn is_valid(&self, sender: Option<UserId>, nonce: Option<Nonce>) -> bool {
        let sender = sender.unwrap_or(self.inputs[0].id);
        if self.inputs.iter().any(|utxo| utxo.id != sender) {
            return false;
        }
        if self.inputs.iter().map(|utxo| utxo.amount).sum::<u64>()
            != self.outputs.iter().map(|utxo| utxo.amount).sum::<u64>()
        {
            return false;
        }
        if nonce.is_some() && nonce != Some(self.nonce) {
            return false;
        }
        true
    }
}

pub type TransactionTree<P: Config> = MerkleTree<P>;

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

#[cfg(test)]
pub mod tests {

    use super::{Transaction, TransactionTreeConfig};
    use crate::{
        datastructures::{
            keypair::constraints::{PublicKeyVar, SignatureVar},
            transaction::{
                constraints::{TransactionTreeConfigGadget, TransactionVar},
                TransactionTree,
            },
            user::User,
        },
        primitives::{crh::constraints::TransactionVarCRH, schnorr::SchnorrGadget},
    };
    use ark_bn254::Fr;
    use ark_crypto_primitives::{
        crh::{poseidon::constraints::CRHParametersVar, CRHSchemeGadget},
        merkle_tree::constraints::PathVar,
    };
    use ark_grumpkin::{constraints::GVar, Projective};
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
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
        let tx_tree =
            TransactionTree::<TransactionTreeConfig<Fr>>::new(&pp, &pp, transactions.clone())
                .unwrap();

        let tx_path = tx_tree.generate_proof(0).unwrap();

        // Tx inclusion circuit
        let cs = ConstraintSystem::<Fr>::new_ref();
        let poseidon_params_var = CRHParametersVar {
            parameters: poseidon_canonical_config(),
        };

        // Initialize root, leaf and path as vars
        let tx_tree_root_var = FpVar::new_witness(cs.clone(), || Ok(tx_tree.root())).unwrap();
        let tx_leaf_var = TransactionVar::new_witness(cs.clone(), || Ok(transactions[0])).unwrap();
        let tx_path_var: PathVar<
            TransactionTreeConfig<Fr>,
            Fr,
            TransactionTreeConfigGadget<TransactionTreeConfig<Fr>, Fr>,
        > = PathVar::new_witness(cs.clone(), || Ok(tx_path)).unwrap();

        // Verify membership
        let res = tx_path_var
            .verify_membership(
                &poseidon_params_var,
                &poseidon_params_var,
                &tx_tree_root_var,
                &tx_leaf_var,
            )
            .unwrap();

        assert!(res.value().unwrap());
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
}
