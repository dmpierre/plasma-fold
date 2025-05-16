use crate::primitives::crh::NonceCRH;

use super::user::UserId;
use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    sponge::Absorb,
};
use ark_ff::PrimeField;
use std::{iter::Map, marker::PhantomData};

pub mod constraints;

pub type NonceMap = Map<UserId, Nonce>;
pub type NonceTree<P: Config> = MerkleTree<P>;

pub struct NonceTreeConfig<F: PrimeField> {
    _f: PhantomData<F>,
}

#[derive(Default, Debug, Clone, Copy, PartialEq)]
pub struct Nonce(pub u64);

impl AsRef<Nonce> for Nonce {
    fn as_ref(&self) -> &Nonce {
        &self
    }
}

impl<F: PrimeField + Absorb> Config for NonceTreeConfig<F> {
    type Leaf = Nonce;
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = NonceCRH<F>;
    type TwoToOneHash = TwoToOneCRH<F>;
}

#[cfg(test)]
pub mod tests {
    use ark_bn254::Fr;
    use ark_crypto_primitives::merkle_tree::constraints::PathVar;
    use ark_ff::UniformRand;
    use ark_grumpkin::Projective;
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::rand::{thread_rng, Rng};
    use folding_schemes::transcript::poseidon::poseidon_canonical_config;

    use crate::{
        circuits::gadgets::{TreeGadgets, TreeUpdateProof},
        datastructures::{
            keypair::{self, KeyPair},
            noncemap::{Nonce, NonceTree, NonceTreeConfig},
            user::{sample_user, User},
        },
    };

    use super::constraints::NonceTreeConfigGadget;

    #[test]
    pub fn test_nonce_map_circuit() {
        let tree_height = 5;
        let n_users = 1 << (tree_height - 1);
        let mut rng = thread_rng();
        let pp = poseidon_canonical_config::<Fr>();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let nonces = (0..n_users)
            .map(|i| Nonce(rng.gen_range(0..(u64::MAX))))
            .collect::<Vec<Nonce>>();
        let nonce_tree = NonceTree::<NonceTreeConfig<Fr>>::new(&pp, &pp, nonces).unwrap();

        for _ in 0..100 {
            let expected_random_user_id = rng.gen_range(0..n_users);
            let user_nonce_proof = nonce_tree.generate_proof(expected_random_user_id).unwrap();
            let expected_random_user_id_var =
                FpVar::new_witness(cs.clone(), || Ok(Fr::from(expected_random_user_id as u32)))
                    .unwrap();
            let user_nonce_proof_var = PathVar::<
                NonceTreeConfig<Fr>,
                Fr,
                NonceTreeConfigGadget<NonceTreeConfig<Fr>, Fr>,
            >::new_witness(cs.clone(), || {
                Ok(user_nonce_proof)
            })
            .unwrap();

            TreeGadgets::compute_id_from_path_and_check(
                &user_nonce_proof_var,
                &expected_random_user_id_var,
            )
            .unwrap();
        }

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    pub fn test_initialize_nonce_tree_and_update() {
        let tree_height = 5;
        let n_users = 1 << (tree_height - 1);
        let mut rng = thread_rng();
        let pp = poseidon_canonical_config::<Fr>();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let users = (0..n_users)
            .map(|i| sample_user(&mut rng))
            .collect::<Vec<User<Projective>>>();
        let initial_nonces = users.iter().map(|u| u.nonce).collect::<Vec<Nonce>>();
    }
}
