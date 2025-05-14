use std::marker::PhantomData;

use crate::{datastructures::user::UserId, primitives::crh::UserIdCRH};
use ark_crypto_primitives::{
    crh::poseidon::TwoToOneCRH,
    merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    sponge::Absorb,
};
use ark_ff::PrimeField;

pub mod constraints;

pub type SignerList = Vec<UserId>;
pub type SignerTree<P: Config> = MerkleTree<P>;

pub struct SignerTreeConfig<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> Config for SignerTreeConfig<F> {
    type Leaf = [UserId];
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = UserIdCRH<F>;
    type TwoToOneHash = TwoToOneCRH<F>;
}

#[cfg(test)]
pub mod tests {
    use ark_bn254::Fr;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::rand::thread_rng;
    use folding_schemes::transcript::poseidon::poseidon_canonical_config;

    use crate::datastructures::user::UserId;

    use super::{SignerTree, SignerTreeConfig};

    #[test]
    pub fn test_signer_tree_constraints() {
        let n_users = (2 as usize).pow(10);
        let mut rng = thread_rng();
        let pp = poseidon_canonical_config::<Fr>();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let user_ids = (0..n_users)
            .map(|id| [id as u32; 1])
            .collect::<Vec<[UserId; 1]>>();
        let signer_tree = SignerTree::<SignerTreeConfig<Fr>>::new(&pp, &pp, user_ids);

        // classic mt, there isn't much to test
        assert!(signer_tree.is_ok());
    }
}
