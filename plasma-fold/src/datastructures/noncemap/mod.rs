use crate::primitives::{
    crh::NonceCRH,
    sparsemt::{MerkleSparseTree, SparseConfig},
};

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
pub type NonceTree<P> = MerkleSparseTree<P>;

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

impl<F: PrimeField + Absorb> SparseConfig for NonceTreeConfig<F> {
    const HEIGHT: u64 = 32;
}

#[cfg(test)]
pub mod tests {
    use std::collections::BTreeMap;

    use ark_bn254::Fr;
    use ark_crypto_primitives::{
        crh::poseidon::constraints::CRHParametersVar, merkle_tree::constraints::PathVar,
    };
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
        primitives::sparsemt::constraints::MerkleSparseTreePathVar,
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
        let nonce_tree = NonceTree::<NonceTreeConfig<Fr>>::new(
            &pp,
            &pp,
            &BTreeMap::from_iter(
                nonces
                    .iter()
                    .enumerate()
                    .map(|(i, &nonce)| (i as u64, nonce)),
            ),
        )
        .unwrap();

        let pp_var = CRHParametersVar::new_constant(cs.clone(), &pp).unwrap();
        let root_var = FpVar::new_constant(cs.clone(), &nonce_tree.root()).unwrap();

        for _ in 0..100 {
            let expected_random_user_id = rng.gen_range(0..n_users);
            let user_nonce_proof = nonce_tree
                .generate_proof(
                    expected_random_user_id,
                    &nonces[expected_random_user_id as usize],
                )
                .unwrap();
            let expected_user_nonce_var =
                FpVar::new_witness(cs.clone(), || Ok(Fr::from(nonces[expected_random_user_id as usize].0)))
                    .unwrap();
            let user_nonce_proof_var =
                MerkleSparseTreePathVar::<_, _, NonceTreeConfigGadget<_>>::new_witness(
                    cs.clone(),
                    || Ok(user_nonce_proof),
                )
                .unwrap();

            user_nonce_proof_var
                .check_membership_with_index(
                    &pp_var,
                    &pp_var,
                    &root_var,
                    &expected_user_nonce_var,
                    &FpVar::Constant(Fr::from(expected_random_user_id)),
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
