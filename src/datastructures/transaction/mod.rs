use super::{utxo::UTXO, TX_IO_SIZE};
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
pub struct Transaction<F: PrimeField> {
    inputs: [UTXO<F>; TX_IO_SIZE],
    outputs: [UTXO<F>; TX_IO_SIZE],
    nonce: F,
}

// TX_IO_SIZE * 4 + 1 for the inputs + outputs + nonce
impl<F: PrimeField> Into<Vec<F>> for Transaction<F> {
    fn into(self) -> Vec<F> {
        let mut input_arr = self.inputs.concat();
        let output_arr = self.outputs.concat();
        input_arr.extend(output_arr);
        input_arr.push(self.nonce);
        input_arr
    }
}

impl<F: PrimeField + Absorb> Absorb for Transaction<F> {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        let tx_vec = Into::<Vec<F>>::into(*self);
        // should be ok to unwrap here since we are just serializing a bunch of field elements, not ideal though
        tx_vec.serialize_uncompressed(dest).unwrap();
    }

    fn to_sponge_field_elements<F_: PrimeField>(&self, dest: &mut Vec<F_>) {
        let tx_vec = Into::<Vec<F>>::into(*self);
        tx_vec.to_sponge_field_elements(dest);
    }
}

pub type TransactionTree<P: Config> = MerkleTree<P>;

pub struct TransactionTreeConfig<F: PrimeField> {
    pub poseidon_conf: PoseidonConfig<F>,
}

impl<F: PrimeField + Absorb> Config for TransactionTreeConfig<F> {
    type Leaf = Transaction<F>;
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = TransactionCRH<F>;
    type TwoToOneHash = TwoToOneCRH<F>;
}
