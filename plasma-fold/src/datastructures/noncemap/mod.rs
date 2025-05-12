use crate::primitives::crh::NonceCRH;

use super::user::UserId;
use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use std::iter::Map;

pub mod constraints;

pub type Nonce = u64;
pub type NonceMap = Map<UserId, Nonce>;
pub type NonceTree<P: Config> = MerkleTree<P>;

pub struct NonceTreeConfig<F: PrimeField> {
    pub poseidon_conf: PoseidonConfig<F>,
}

impl<F: PrimeField + Absorb> Config for NonceTreeConfig<F> {
    type Leaf = [Nonce];
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = NonceCRH<F>;
    type TwoToOneHash = TwoToOneCRH<F>;
}

#[cfg(test)]
pub mod tests {
    use ark_bn254::Fr;
    use ark_grumpkin::Projective;
    use ark_std::rand::thread_rng;
    use folding_schemes::transcript::poseidon::poseidon_canonical_config;

    use crate::datastructures::{
        noncemap::{Nonce, NonceTree, NonceTreeConfig},
        user::User,
    };

    #[test]
    pub fn test_nonce_map_circuit() {
        let mut rng = thread_rng();
        let pp = poseidon_canonical_config::<Fr>();
        let n_users = (2 as usize).pow(5);
        let mut users = (0..n_users)
            .map(|i| User::new(&mut rng, i as u32))
            .collect::<Vec<User<Projective>>>();

        // making up a non zero nonce for user with id 1
        users[1].nonce = 10;
        let nonces = users
            .iter()
            .map(|user| [user.nonce])
            .collect::<Vec<[Nonce; 1]>>();
        let nonce_tree = NonceTree::<NonceTreeConfig<Fr>>::new(&pp, &pp, &nonces).unwrap();
    }
}
