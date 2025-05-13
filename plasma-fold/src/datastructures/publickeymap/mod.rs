use crate::primitives::crh::PublicKeyCRH;
use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    sponge::{poseidon::PoseidonConfig, Absorb},
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use std::{iter::Map, marker::PhantomData};

use super::{keypair::PublicKey, user::UserId};

pub mod constraints;

pub type PublicKeyMap<C: CurveGroup> = Map<UserId, PublicKey<C>>;
pub type PublicKeyTree<P: Config> = MerkleTree<P>;

impl<C: CurveGroup<BaseField: PrimeField + Absorb>> Absorb for PublicKey<C> {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        let (x, y) = self.key.into_affine().xy().unwrap();
        dest.extend(x.into_bigint().to_bytes_le());
        dest.extend(y.into_bigint().to_bytes_le());
    }

    fn to_sponge_field_elements<F_: PrimeField>(&self, dest: &mut Vec<F_>) {
        let (x, y) = self.key.into_affine().xy().unwrap();
        x.to_sponge_field_elements(dest);
        y.to_sponge_field_elements(dest);
    }
}

pub struct PublicKeyTreeConfig<C: CurveGroup<BaseField: PrimeField + Absorb>> {
    pub poseidon_conf: PoseidonConfig<C::BaseField>,
    _c: PhantomData<C>,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>> Config for PublicKeyTreeConfig<C> {
    type Leaf = PublicKey<C>;
    type LeafDigest = C::BaseField;
    type LeafInnerDigestConverter = IdentityDigestConverter<C::BaseField>;
    type InnerDigest = C::BaseField;
    type LeafHash = PublicKeyCRH<C>;
    type TwoToOneHash = TwoToOneCRH<C::BaseField>;
}

#[cfg(test)]
pub mod tests {
    use ark_bn254::Fr;
    use ark_crypto_primitives::merkle_tree::constraints::PathVar;
    use ark_ff::UniformRand;
    use ark_grumpkin::{constraints::GVar, Projective};
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::rand::{thread_rng, Rng};
    use folding_schemes::transcript::poseidon::poseidon_canonical_config;

    use crate::{
        circuits::gadgets::TreeGadgets,
        datastructures::{
            keypair::PublicKey,
            publickeymap::{
                constraints::PublicKeyTreeConfigGadget, PublicKeyTree, PublicKeyTreeConfig,
            },
        },
    };

    #[test]
    pub fn test_public_key_tree_circuit() {
        let n_users = (2 as usize).pow(10);
        let mut rng = thread_rng();
        let pp = poseidon_canonical_config::<Fr>();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let public_keys = (0..n_users)
            .map(|i| {
                let key = Projective::rand(&mut rng);
                PublicKey { key }
            })
            .collect::<Vec<PublicKey<Projective>>>();
        let public_key_tree =
            PublicKeyTree::<PublicKeyTreeConfig<Projective>>::new(&pp, &pp, &public_keys).unwrap();

        for _ in 0..100 {
            let expected_random_user_id = rng.gen_range(0..n_users);
            let user_public_key_proof = public_key_tree
                .generate_proof(expected_random_user_id)
                .unwrap();
            let expected_random_user_id_var =
                FpVar::new_witness(cs.clone(), || Ok(Fr::from(expected_random_user_id as u32)))
                    .unwrap();
            let public_key_proof_var =
                PathVar::<
                    PublicKeyTreeConfig<Projective>,
                    Fr,
                    PublicKeyTreeConfigGadget<Projective, GVar, PublicKeyTreeConfig<Projective>>,
                >::new_witness(cs.clone(), || Ok(user_public_key_proof))
                .unwrap();

            TreeGadgets::compute_id_and_check(&public_key_proof_var, &expected_random_user_id_var)
                .unwrap();
        }

        assert!(cs.is_satisfied().unwrap());
    }
}
