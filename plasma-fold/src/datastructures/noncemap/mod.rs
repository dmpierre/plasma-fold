use crate::primitives::crh::NonceCRH;

use super::user::UserId;
use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{
        constraints::{ConfigGadget, PathVar},
        Config, IdentityDigestConverter, MerkleTree,
    },
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, prelude::Boolean, R1CSVar};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, SynthesisError};
use std::{iter::Map, marker::PhantomData};

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

pub struct NonceTreeGadgets<P: Config, F: PrimeField, PG: ConfigGadget<P, F>> {
    _f: PhantomData<P>,
    _f1: PhantomData<F>,
    _f2: PhantomData<PG>,
}

impl<P: Config, F: PrimeField, PG: ConfigGadget<P, F>> NonceTreeGadgets<P, F, PG> {
    pub fn compute_id_and_check(
        cs: ConstraintSystemRef<F>,
        nonce_path: &PathVar<P, F, PG>,
        expected_id: &FpVar<F>,
    ) -> Result<Boolean<F>, SynthesisError> {
        let mut computed_id = Boolean::<F>::le_bits_to_fp(&nonce_path.get_leaf_position())?;
        Ok(computed_id.is_eq(&expected_id)?)
    }
}

#[cfg(test)]
pub mod tests {
    use ark_bn254::Fr;
    use ark_crypto_primitives::merkle_tree::constraints::PathVar;
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::rand::{thread_rng, Rng};
    use folding_schemes::transcript::poseidon::poseidon_canonical_config;

    use crate::datastructures::noncemap::{NonceTree, NonceTreeConfig};

    use super::{constraints::NonceTreeConfigGadget, NonceTreeGadgets};

    #[test]
    pub fn test_nonce_map_circuit() {
        let n_users = (2 as usize).pow(10);
        let mut rng = thread_rng();
        let pp = poseidon_canonical_config::<Fr>();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let nonces = (0..n_users)
            .map(|i| [rng.gen_range(0..(u64::MAX)); 1])
            .collect::<Vec<[u64; 1]>>();
        let nonce_tree = NonceTree::<NonceTreeConfig<Fr>>::new(&pp, &pp, nonces).unwrap();

        for i in 0..100 {
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

            let res = NonceTreeGadgets::compute_id_and_check(
                cs.clone(),
                &user_nonce_proof_var,
                &expected_random_user_id_var,
            )
            .unwrap();
            assert!(cs.is_satisfied().unwrap());
            assert!(res.value().unwrap());
        }
    }
}
