use crate::datastructures::user::UserId;
use ark_crypto_primitives::{
    crh::poseidon::{TwoToOneCRH, CRH},
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ff::PrimeField;

pub type SignerList<F: PrimeField> = Vec<UserId<F>>;

pub type SignerTree<P: Config> = MerkleTree<P>;

pub struct SignerTreeConfig<F: PrimeField> {
    pub poseidon_conf: PoseidonConfig<F>,
}

impl<F: PrimeField + Absorb> Config for SignerTreeConfig<F> {
    type Leaf = [F];
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = CRH<F>;
    type TwoToOneHash = TwoToOneCRH<F>;
}
