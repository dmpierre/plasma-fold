use ark_crypto_primitives::{
    crh::{
        poseidon::{constraints::TwoToOneCRHGadget, TwoToOneCRH, CRH},
        CRHSchemeGadget, TwoToOneCRHSchemeGadget,
    },
    merkle_tree::{constraints::ConfigGadget, Config},
    sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    fields::fp::FpVar,
    prelude::Boolean,
    R1CSVar,
};
use ark_r1cs_std::{prelude::ToBitsGadget, select::CondSelectGadget};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use std::{borrow::Borrow, ops::Not};

use crate::primitives::crh::UTXOCRH;

use super::{MerkleSparseTreePath, MerkleSparseTreeTwoPaths, SparseConfig};

pub trait SparseConfigGadget<P: Config, F: PrimeField>: ConfigGadget<P, F> {
    const HEIGHT: u64;
}

/// Gadgets for one Merkle tree path
#[derive(Debug)]
pub struct MerkleSparseTreePathVar<MP: Config, F: PrimeField, P: SparseConfigGadget<MP, F>> {
    path: Vec<(P::InnerDigest, P::InnerDigest)>,
}

/// Gadgets for two Merkle tree paths
#[derive(Debug)]
pub struct MerkleSparseTreeTwoPathsVar<MP: Config, F: PrimeField, P: SparseConfigGadget<MP, F>> {
    old_path: Vec<(P::InnerDigest, P::InnerDigest)>,
    new_path: Vec<(P::InnerDigest, P::InnerDigest)>,
}

impl<
        MP: Config<LeafHash = UTXOCRH<F>, TwoToOneHash = TwoToOneCRH<F>>,
        F: PrimeField + Absorb,
        P: SparseConfigGadget<
            MP,
            F,
            LeafDigest = FpVar<F>,
            InnerDigest = FpVar<F>,
            TwoToOneHash = TwoToOneCRHGadget<F>,
        >,
    > MerkleSparseTreePathVar<MP, F, P>
{
    /// check a lookup proof (does not enforce index consistency)
    pub fn check_membership(
        &self,
        cs: ConstraintSystemRef<F>,
        leaf_hash_params: &<P::LeafHash as CRHSchemeGadget<MP::LeafHash, F>>::ParametersVar,
        two_to_one_hash_params: &<P::TwoToOneHash as TwoToOneCRHSchemeGadget<
            MP::TwoToOneHash,
            F,
        >>::ParametersVar,
        root: &P::InnerDigest,
        leaf: &P::Leaf,
    ) -> Result<(), SynthesisError> {
        self.conditionally_check_membership(
            cs,
            leaf_hash_params,
            two_to_one_hash_params,
            root,
            leaf,
            &Boolean::Constant(true),
        )
    }

    /// conditionally check a lookup proof (does not enforce index consistency)
    pub fn conditionally_check_membership(
        &self,
        cs: ConstraintSystemRef<F>,
        leaf_hash_params: &<P::LeafHash as CRHSchemeGadget<MP::LeafHash, F>>::ParametersVar,
        two_to_one_hash_params: &<P::TwoToOneHash as TwoToOneCRHSchemeGadget<
            MP::TwoToOneHash,
            F,
        >>::ParametersVar,
        root: &P::InnerDigest,
        leaf: &P::Leaf,
        should_enforce: &Boolean<F>,
    ) -> Result<(), SynthesisError> {
        assert_eq!(self.path.len(), (P::HEIGHT - 1) as usize);
        // Check that the hash of the given leaf matches the leaf hash in the membership
        // proof.
        // let leaf_bits = leaf.to_bytes()?;
        let leaf_hash =
            <P::LeafHash as CRHSchemeGadget<MP::LeafHash, F>>::evaluate(leaf_hash_params, &leaf)?;
        // let leaf_hash = CRHVar::hash_bytes(parameters, &leaf_bits)?;

        // Check if leaf is one of the bottom-most siblings.
        let leaf_is_left = Ok(Boolean::new_witness(
            ark_relations::ns!(cs, "leaf_is_left"),
            || Ok(leaf_hash.value()? == self.path[0].0.value()?),
        )?)?;

        leaf_hash.conditional_enforce_equal(
            &<P::LeafHash as CRHSchemeGadget<MP::LeafHash, F>>::OutputVar::conditionally_select(
                &leaf_is_left,
                &self.path[0].0,
                &self.path[0].1,
            )?,
            should_enforce,
        )?;

        // Check levels between leaf level and root.
        let mut previous_hash = leaf_hash;
        for &(ref left_hash, ref right_hash) in self.path.iter() {
            // Check if the previous_hash matches the correct current hash.
            let previous_is_left =
                Boolean::new_witness(ark_relations::ns!(cs, "previous_is_left"), || {
                    Ok(previous_hash.value()? == left_hash.value()?)
                })?;

            previous_hash.conditional_enforce_equal(
                &<P::LeafHash as CRHSchemeGadget<MP::LeafHash, F>>::OutputVar::conditionally_select(
                    &previous_is_left,
                    left_hash,
                    right_hash,
                )?,
                should_enforce,
            )?;

            previous_hash =
                <P::TwoToOneHash as TwoToOneCRHSchemeGadget<MP::TwoToOneHash, F>>::evaluate(
                    two_to_one_hash_params,
                    left_hash,
                    right_hash,
                )?;
            //previous_hash = hash_inner_node_gadget::<P::H, CRHVar, ConstraintF>(
            //    parameters, left_hash, right_hash,
            //)?;
        }

        root.conditional_enforce_equal(&previous_hash, should_enforce)
    }

    /// check a lookup proof (with index)
    pub fn check_membership_with_index(
        &self,
        leaf_hash_params: &<P::LeafHash as CRHSchemeGadget<MP::LeafHash, F>>::ParametersVar,
        two_to_one_hash_params: &<P::TwoToOneHash as TwoToOneCRHSchemeGadget<
            MP::TwoToOneHash,
            F,
        >>::ParametersVar,
        root: &P::InnerDigest,
        leaf: &P::Leaf,
        index: &FpVar<F>,
    ) -> Result<(), SynthesisError> {
        self.conditionally_check_membership_with_index(
            leaf_hash_params,
            two_to_one_hash_params,
            root,
            leaf,
            index,
            &Boolean::Constant(true),
        )
    }

    /// conditionally check a lookup proof (with index)
    pub fn conditionally_check_membership_with_index(
        &self,
        leaf_hash_params: &<P::LeafHash as CRHSchemeGadget<MP::LeafHash, F>>::ParametersVar,
        two_to_one_hash_params: &<P::TwoToOneHash as TwoToOneCRHSchemeGadget<
            MP::TwoToOneHash,
            F,
        >>::ParametersVar,
        root: &P::InnerDigest,
        leaf: &P::Leaf,
        index: &FpVar<F>,
        should_enforce: &Boolean<F>,
    ) -> Result<(), SynthesisError> {
        assert_eq!(self.path.len(), (P::HEIGHT - 1) as usize);
        // Check that the hash of the given leaf matches the leaf hash in the membership
        // proof.
        //let leaf_bits = leaf.to_bytes()?;
        //let leaf_hash = CRHVar::hash_bytes(parameters, &leaf_bits)?;
        let leaf_hash =
            <P::LeafHash as CRHSchemeGadget<MP::LeafHash, F>>::evaluate(leaf_hash_params, leaf)?;

        // Check levels between leaf level and root.
        let mut previous_hash = leaf_hash;
        let index_bits = index.to_bits_le()?;

        for (i, &(ref left_hash, ref right_hash)) in self.path.iter().enumerate() {
            // Check if the previous_hash matches the correct current hash.
            let previous_is_left = index_bits[i].clone().not();

            previous_hash.conditional_enforce_equal(
                &<P::LeafHash as CRHSchemeGadget<MP::LeafHash, F>>::OutputVar::conditionally_select(&previous_is_left, left_hash, right_hash)?,
                should_enforce,
            )?;

            previous_hash =
                <P::TwoToOneHash as TwoToOneCRHSchemeGadget<MP::TwoToOneHash, F>>::evaluate(
                    two_to_one_hash_params,
                    left_hash,
                    right_hash,
                )?;
        }

        root.conditional_enforce_equal(&previous_hash, should_enforce)
    }
}

//pub(crate) fn hash_inner_node_gadget<H, HG, ConstraintF>(
//    parameters: &H::Parameters,
//    left_child: &HG::OutputVar,
//    right_child: &HG::OutputVar,
//) -> Result<HG::OutputVar, SynthesisError>
//where
//    ConstraintF: PrimeField,
//    H: CRHforMerkleTree,
//    HG: CRHforMerkleTreeGadget<H, ConstraintF>,
//{
//    HG::two_to_one_compress(parameters, left_child, right_child)
//}
//

impl<
        MP: Config<TwoToOneHash = TwoToOneCRH<F>>,
        F: PrimeField + Absorb,
        P: SparseConfigGadget<
            MP,
            F,
            LeafDigest = FpVar<F>,
            InnerDigest = FpVar<F>,
            TwoToOneHash = TwoToOneCRHGadget<F>,
        >,
    > MerkleSparseTreeTwoPathsVar<MP, F, P>
{
    /// check a modifying proof
    pub fn check_update(
        &self,
        leaf_hash_params: &<P::LeafHash as CRHSchemeGadget<MP::LeafHash, F>>::ParametersVar,
        two_to_one_hash_params: &<P::TwoToOneHash as TwoToOneCRHSchemeGadget<
            MP::TwoToOneHash,
            F,
        >>::ParametersVar,
        old_root: &P::InnerDigest,
        new_root: &P::InnerDigest,
        new_leaf: &P::Leaf,
        index: &FpVar<F>,
    ) -> Result<(), SynthesisError> {
        self.conditionally_check_update(
            leaf_hash_params,
            two_to_one_hash_params,
            old_root,
            new_root,
            new_leaf,
            index,
            &Boolean::Constant(true),
        )
    }

    /// conditionally check a modifying proof
    pub fn conditionally_check_update(
        &self,
        leaf_hash_params: &<P::LeafHash as CRHSchemeGadget<MP::LeafHash, F>>::ParametersVar,
        two_to_one_hash_params: &<P::TwoToOneHash as TwoToOneCRHSchemeGadget<
            MP::TwoToOneHash,
            F,
        >>::ParametersVar,
        old_root: &P::InnerDigest,
        new_root: &P::InnerDigest,
        new_leaf: &P::Leaf,
        index: &FpVar<F>,
        should_enforce: &Boolean<F>,
    ) -> Result<(), SynthesisError> {
        assert_eq!(self.old_path.len(), (P::HEIGHT - 1) as usize);
        assert_eq!(self.new_path.len(), (P::HEIGHT - 1) as usize);
        // Check that the hash of the given leaf matches the leaf hash in the membership
        // proof.
        //let new_leaf_bits = new_leaf.to_bytes()?;
        //let new_leaf_hash = CRHVar::hash_bytes(parameters, &new_leaf_bits)?;

        let new_leaf_hash = <P::LeafHash as CRHSchemeGadget<MP::LeafHash, F>>::evaluate(
            leaf_hash_params,
            &new_leaf,
        )?;

        // Check levels between leaf level and root of the new tree.
        let mut previous_hash = new_leaf_hash;
        let index_bits = index.to_bits_le()?;
        for (i, &(ref left_hash, ref right_hash)) in self.new_path.iter().enumerate() {
            // Check if the previous_hash matches the correct current hash.
            let previous_is_left = index_bits[i].clone().not();

            //previous_hash.conditional_enforce_equal(
            //    &CRHVar::OutputVar::conditionally_select(&previous_is_left, left_hash, right_hash)?,
            //    should_enforce,
            //)?;

            previous_hash.conditional_enforce_equal(
                &<P::LeafHash as CRHSchemeGadget<MP::LeafHash, F>>::OutputVar::conditionally_select(
                    &previous_is_left,
                    left_hash,
                    right_hash,
                )?,
                should_enforce,
            )?;

            previous_hash =
                <P::TwoToOneHash as TwoToOneCRHSchemeGadget<MP::TwoToOneHash, F>>::evaluate(
                    two_to_one_hash_params,
                    left_hash,
                    right_hash,
                )?;
            //previous_hash = hash_inner_node_gadget::<P::H, CRHVar, ConstraintF>(
            //    parameters, left_hash, right_hash,
            //)?;
        }

        new_root.conditional_enforce_equal(&previous_hash, should_enforce)?;

        let mut old_path_iter = self.old_path.iter();
        let old_path_first_entry = old_path_iter.next().unwrap();

        previous_hash =
            <P::TwoToOneHash as TwoToOneCRHSchemeGadget<MP::TwoToOneHash, F>>::evaluate(
                two_to_one_hash_params,
                &old_path_first_entry.0,
                &old_path_first_entry.1,
            )?;
        //previous_hash = hash_inner_node_gadget::<P::H, CRHVar, ConstraintF>(
        //    parameters,
        //    &old_path_first_entry.0,
        //    &old_path_first_entry.1,
        //)?;

        let mut current_loc = 1;
        loop {
            let pair = old_path_iter.next();

            match pair {
                Some((left_hash, right_hash)) => {
                    // Check if the previous_hash matches the correct current hash.
                    let previous_is_left = index_bits[current_loc].clone().not();

                    previous_hash.conditional_enforce_equal(
                        &<P::LeafHash as CRHSchemeGadget<MP::LeafHash, F>>::OutputVar::conditionally_select(
                            &previous_is_left,
                            left_hash,
                            right_hash,
                        )?,
                        should_enforce,
                    )?;

                    previous_hash = <P::TwoToOneHash as TwoToOneCRHSchemeGadget<
                        MP::TwoToOneHash,
                        F,
                    >>::evaluate(
                        two_to_one_hash_params, left_hash, right_hash
                    )?;
                    //previous_hash = hash_inner_node_gadget::<P::H, CRHVar, ConstraintF>(
                    //    parameters, left_hash, right_hash,
                    //)?;
                }
                None => break,
            }
            current_loc += 1;
        }

        old_path_iter = self.old_path.iter();
        for (i, &(ref left_hash, ref right_hash)) in self.new_path.iter().enumerate() {
            // Check if the previous_hash matches the correct current hash.
            let previous_is_left = index_bits[i].clone().not();
            let previous_is_right = previous_is_left.clone().not();

            let old_path_corresponding_entry = old_path_iter.next().unwrap();

            right_hash
                .conditional_enforce_equal(&old_path_corresponding_entry.1, &previous_is_left)?;

            left_hash
                .conditional_enforce_equal(&old_path_corresponding_entry.0, &previous_is_right)?;
        }

        old_root.conditional_enforce_equal(&previous_hash, should_enforce)
    }
}

impl<MP: SparseConfig, F: PrimeField, P: SparseConfigGadget<MP, F>>
    AllocVar<MerkleSparseTreePath<MP>, F> for MerkleSparseTreePathVar<MP, F, P>
{
    fn new_variable<T: Borrow<MerkleSparseTreePath<MP>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let mut path = Vec::new();
        for &(ref l, ref r) in f()?.borrow().path.iter() {
            let l_hash = P::InnerDigest::new_variable(
                ark_relations::ns!(cs, "l_child"),
                || Ok(l.clone()),
                mode,
            )?;
            let r_hash = P::InnerDigest::new_variable(
                ark_relations::ns!(cs, "r_child"),
                || Ok(r.clone()),
                mode,
            )?;
            path.push((l_hash, r_hash));
        }
        Ok(MerkleSparseTreePathVar { path })
    }
}

impl<MP: SparseConfig, F: PrimeField, P: SparseConfigGadget<MP, F>>
    AllocVar<MerkleSparseTreeTwoPaths<MP>, F> for MerkleSparseTreeTwoPathsVar<MP, F, P>
{
    fn new_variable<T: Borrow<MerkleSparseTreeTwoPaths<MP>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let mut old_path = Vec::new();

        let t = f()?;
        let paths = t.borrow();
        for &(ref l, ref r) in paths.old_path.path.iter() {
            let l_hash = P::InnerDigest::new_variable(
                ark_relations::ns!(cs, "old_path_l_child"),
                || Ok(l.clone()),
                mode,
            )?;
            let r_hash = P::InnerDigest::new_variable(
                ark_relations::ns!(cs, "old_path_r_child"),
                || Ok(r.clone()),
                mode,
            )?;
            old_path.push((l_hash, r_hash));
        }
        let mut new_path = Vec::new();
        for &(ref l, ref r) in paths.new_path.path.iter() {
            let l_hash = P::InnerDigest::new_variable(
                ark_relations::ns!(cs, "new_path_l_child"),
                || Ok(l.clone()),
                mode,
            )?;
            let r_hash = P::InnerDigest::new_variable(
                ark_relations::ns!(cs, "new_path_r_child"),
                || Ok(r.clone()),
                mode,
            )?;
            new_path.push((l_hash, r_hash));
        }
        Ok(MerkleSparseTreeTwoPathsVar { old_path, new_path })
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use crate::datastructures::utxo::constraints::{UTXOTreeConfigGadget, UTXOVar};
    use crate::datastructures::utxo::{UTXOTreeConfig, UTXO};
    use crate::primitives::crh::constraints::UTXOVarCRH;
    use crate::primitives::sparsemt::MerkleSparseTree;
    use ark_bn254::Fr;
    use ark_crypto_primitives::crh::poseidon::constraints::CRHParametersVar;
    use ark_crypto_primitives::crh::CRHScheme;
    use ark_relations::r1cs::ConstraintSystem;
    use folding_schemes::transcript::poseidon::poseidon_canonical_config;

    use super::*;

    impl SparseConfigGadget<UTXOTreeConfig<Fr>, Fr> for UTXOTreeConfigGadget<Fr> {
        const HEIGHT: u64 = 32;
    }

    type UTXOMerkleTree = MerkleSparseTree<UTXOTreeConfig<Fr>>;
    type H = UTXOCRH<Fr>;
    type HG = UTXOVarCRH<Fr>;

    fn generate_merkle_tree(leaves: &BTreeMap<u64, UTXO>, use_bad_root: bool) -> usize {
        let pp = poseidon_canonical_config();

        let tree = UTXOMerkleTree::new(&pp, &pp, leaves).unwrap();
        let root = tree.root();

        let cs_sys = ConstraintSystem::<Fr>::new();
        let cs = ConstraintSystemRef::new(cs_sys);
        let pp_var = CRHParametersVar::new_witness(cs.clone(), || Ok(pp.clone())).unwrap();

        let pp_var_constraints = cs.num_constraints();
        let mut satisfied = true;
        for (i, leaf) in leaves.iter() {
            let proof = tree.generate_proof(*i, &leaf).unwrap();
            assert!(proof.verify(&pp, &pp, &root, &leaf).unwrap());

            // Allocate Merkle Tree Root
            let root = <HG as CRHSchemeGadget<H, Fr>>::OutputVar::new_witness(
                ark_relations::ns!(cs, "new_digest"),
                || {
                    if use_bad_root {
                        Ok(<H as CRHScheme>::Output::default())
                    } else {
                        Ok(root)
                    }
                },
            )
            .unwrap();

            // Allocate Leaf
            let leaf_g = UTXOVar::new_constant(cs.clone(), leaf).unwrap();
            let index_g = FpVar::new_constant(cs.clone(), Fr::from(*i)).unwrap();

            // Allocate Merkle Tree Path
            let cw = MerkleSparseTreePathVar::<UTXOTreeConfig<Fr>, Fr, UTXOTreeConfigGadget<Fr>>::new_witness(
                ark_relations::ns!(cs, "new_witness"),
                || Ok(proof),
            )
            .unwrap();

            cw.check_membership(
                ark_relations::ns!(cs, "check_membership").cs(),
                &pp_var,
                &pp_var,
                &root,
                &leaf_g,
            )
            .unwrap();
            cw.check_membership_with_index(&pp_var, &pp_var, &root, &leaf_g, &index_g)
                .unwrap();
            if !cs.is_satisfied().unwrap() {
                satisfied = false;
                println!(
                    "Unsatisfied constraint: {}",
                    cs.which_is_unsatisfied().unwrap().unwrap()
                );
            }
        }

        assert!(satisfied);
        cs.num_constraints() - pp_var_constraints
    }

    #[test]
    fn good_root_membership_test() {
        let mut leaves = BTreeMap::new();
        for i in 1..10u8 {
            leaves.insert(
                i as u64,
                UTXO {
                    amount: (10 * i) as u64,
                    id: i as u32,
                },
            );
        }
        let n_constraints = generate_merkle_tree(&leaves, false);
        println!("good_root_membership_test n constraints: {}", n_constraints);
    }

    #[should_panic]
    #[test]
    fn bad_root_membership_test() {
        let mut leaves = BTreeMap::new();
        for i in 1..10u8 {
            leaves.insert(
                i as u64,
                UTXO {
                    amount: (10 * i) as u64,
                    id: i as u32,
                },
            );
        }
        generate_merkle_tree(&leaves, true);
    }

    fn generate_merkle_tree_and_test_update(
        old_leaves: &BTreeMap<u64, UTXO>,
        new_leaves: &BTreeMap<u64, UTXO>,
    ) -> usize {
        let pp = poseidon_canonical_config();
        let mut tree = UTXOMerkleTree::new(&pp, &pp, old_leaves).unwrap();
        let mut satisfied = true;
        let cs_sys = ConstraintSystem::<Fr>::new();
        let cs = ConstraintSystemRef::new(cs_sys);
        let pp_var = CRHParametersVar::new_witness(cs.clone(), || Ok(pp.clone())).unwrap();

        let pp_var_constraints = cs.num_constraints();

        for (i, new_leaf) in new_leaves.iter() {
            let old_root = tree.root.unwrap();
            let update_proof = tree.update_and_prove(*i, &new_leaf).unwrap();
            let new_leaf_membership_proof = tree.generate_proof(*i, &new_leaf).unwrap();
            let new_root = tree.root.unwrap();

            assert!(update_proof
                .verify(&pp, &pp, &old_root, &new_root, &new_leaf, *i)
                .unwrap());
            assert!(new_leaf_membership_proof
                .verify_with_index(&pp, &pp, &new_root, &new_leaf, *i)
                .unwrap());

            // Allocate Merkle Tree Root
            let old_root_gadget = <HG as CRHSchemeGadget<UTXOCRH<Fr>, Fr>>::OutputVar::new_witness(
                ark_relations::ns!(cs, "old_digest"),
                || Ok(old_root),
            )
            .unwrap();
            let new_root_gadget = <HG as CRHSchemeGadget<UTXOCRH<Fr>, Fr>>::OutputVar::new_witness(
                ark_relations::ns!(cs, "new_digest"),
                || Ok(new_root),
            )
            .unwrap();

            // Allocate Leaf
            let leaf_g =
                UTXOVar::new_variable_with_inferred_mode(cs.clone(), || Ok(new_leaf)).unwrap();
            let index_g = FpVar::new_constant(cs.clone(), Fr::from(*i)).unwrap();

            // Allocate Merkle Tree Path
            let update_proof_cw = MerkleSparseTreeTwoPathsVar::<
                UTXOTreeConfig<Fr>,
                Fr,
                UTXOTreeConfigGadget<Fr>,
            >::new_witness(
                ark_relations::ns!(cs, "new_witness_update"),
                || Ok(update_proof),
            )
            .unwrap();

            let new_leaf_membership_proof_cw = MerkleSparseTreePathVar::<
                UTXOTreeConfig<Fr>,
                Fr,
                UTXOTreeConfigGadget<Fr>,
            >::new_witness(
                ark_relations::ns!(cs, "new_witness_new_membership"),
                || Ok(new_leaf_membership_proof),
            )
            .unwrap();

            update_proof_cw
                .check_update(
                    &pp_var,
                    &pp_var,
                    &old_root_gadget,
                    &new_root_gadget,
                    &leaf_g,
                    &index_g,
                )
                .unwrap();
            new_leaf_membership_proof_cw
                .check_membership_with_index(&pp_var, &pp_var, &new_root_gadget, &leaf_g, &index_g)
                .unwrap();
            if !cs.is_satisfied().unwrap() {
                satisfied = false;
                println!(
                    "Unsatisfied constraint: {}",
                    cs.which_is_unsatisfied().unwrap().unwrap()
                );
            }
        }

        assert!(satisfied);
        cs.num_constraints() - pp_var_constraints
    }

    #[test]
    fn good_root_update_test() {
        let mut old_leaves = BTreeMap::new();
        for i in 1..4u64 {
            old_leaves.insert(
                i,
                UTXO {
                    amount: 10 * i,
                    id: i as u32,
                },
            );
        }

        let mut new_leaves = BTreeMap::new();
        for i in 1..4u64 {
            new_leaves.insert(
                i as u64,
                UTXO {
                    amount: 100 * i,
                    id: i as u32,
                },
            );
        }
        let n_constraints = generate_merkle_tree_and_test_update(&old_leaves, &new_leaves);
        println!("good_root_update_test n constraints: {}", n_constraints);
    }
}
