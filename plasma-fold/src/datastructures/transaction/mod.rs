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

// TX_IO_SIZE * 4 + 1 for the inputs + outputs + nonce
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
        todo!()
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
