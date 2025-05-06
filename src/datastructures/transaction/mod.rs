use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;

use crate::primitives::crh::TransactionCRH;

use super::{utxo::UTXO, TX_ARRAY_SIZE, TX_IO_SIZE};

#[derive(Clone, Copy, Default, CanonicalSerialize)]
pub struct Transaction<F: PrimeField> {
    inputs: [UTXO<F>; TX_IO_SIZE],
    outputs: [UTXO<F>; TX_IO_SIZE],
    nonce: F,
}

// TX_IO_SIZE * 4 + 1 for the inputs + outputs + nonce
impl<F: PrimeField> Into<Vec<F>> for Transaction<F> {
    fn into(self) -> Vec<F> {
        let mut res = [F::ZERO; TX_ARRAY_SIZE];
        let mut input_arr = self.inputs.concat();
        let output_arr = self.outputs.concat();
        input_arr.extend(output_arr);
        input_arr.push(self.nonce);
        input_arr
    }
}

impl<F: PrimeField> Absorb for Transaction<F> {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        let tx_vec = Into::<Vec<F>>::into(*self);
        // should be ok to unwrap here since we are just serializing a bunch of field elements, not ideal though
        tx_vec.serialize_uncompressed(dest).unwrap();
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        let tx_vec = Into::<Vec<F>>::into(*self);
        dest.copy_from_slice(tx_vec.as_slice());
        todo!()
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
