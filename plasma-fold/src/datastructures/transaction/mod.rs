use super::{noncemap::Nonce, user::UserId, utxo::UTXO, TX_IO_SIZE};
use crate::primitives::crh::TransactionCRH;
use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    sponge::{poseidon::PoseidonConfig, Absorb},
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
    pub poseidon_conf: PoseidonConfig<F>,
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
    use crate::datastructures::transaction::constraints::TransactionTreeConfigGadget;
    use crate::datastructures::transaction::constraints::TransactionVar;
    use crate::datastructures::transaction::TransactionTree;
    use ark_bn254::Fr;
    use ark_crypto_primitives::{
        crh::poseidon::constraints::CRHParametersVar, merkle_tree::constraints::PathVar,
    };
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;
    use folding_schemes::transcript::poseidon::poseidon_canonical_config;

    #[test]
    pub fn test_transaction_tree() {
        let tx_tree_height = 10;
        let n_transactions = (2 as usize).pow(tx_tree_height);
        let tx_tree_conf = TransactionTreeConfig {
            poseidon_conf: poseidon_canonical_config(),
        };

        // Build tx tree
        let transactions = (0..n_transactions)
            .map(|_| Transaction::default())
            .collect::<Vec<Transaction>>();
        let tx_tree = TransactionTree::<TransactionTreeConfig<Fr>>::new(
            &tx_tree_conf.poseidon_conf,
            &tx_tree_conf.poseidon_conf,
            transactions.clone(),
        )
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
}
