// adapted from: https://github.com/arkworks-rs/ivls/blob/master/src/building_blocks/mt/merkle_sparse_tree/mod.rs

use ark_crypto_primitives::{
    crh::{poseidon::TwoToOneCRH, CRHScheme, TwoToOneCRHScheme},
    merkle_tree::Config,
    sponge::Absorb,
    Error,
};
use ark_ff::PrimeField;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
};

pub mod constraints;

#[derive(Debug)]
pub enum SparseMTError {
    GenericError,
}

impl Display for SparseMTError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SparseMTError")?;
        Ok(())
    }
}

impl ark_std::error::Error for SparseMTError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }

    fn description(&self) -> &str {
        "description() is deprecated; use Display"
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        self.source()
    }

    fn provide<'a>(&'a self, _request: &mut std::error::Request<'a>) {
        todo!()
    }
}

pub trait SparseConfig: Config<Leaf: Default> {
    const HEIGHT: u64;
}

pub struct MerkleSparseTree<P: SparseConfig> {
    pub tree: BTreeMap<u64, P::LeafDigest>,
    leaf_hash_params: <P::LeafHash as CRHScheme>::Parameters,
    two_to_one_hash_params: <P::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
    root: Option<P::InnerDigest>,
    empty_hashes: Vec<P::InnerDigest>,
}

/// Stores the hashes of a particular path (in order) from leaf to root.
/// Our path `is_left_child()` if the boolean in `path` is true.
#[derive(Clone, Debug)]
pub struct MerkleSparseTreePath<P: SparseConfig> {
    pub path: Vec<(P::InnerDigest, P::InnerDigest)>,
}

/// A modifying proof, consisting of two Merkle tree paths
#[derive(Debug, Clone)]
pub struct MerkleSparseTreeTwoPaths<P: SparseConfig> {
    pub path: Vec<P::InnerDigest>,
}

impl<P: SparseConfig> Default for MerkleSparseTreePath<P> {
    fn default() -> Self {
        let mut path = Vec::with_capacity(P::HEIGHT as usize);
        for _i in 1..P::HEIGHT as usize {
            path.push((P::InnerDigest::default(), P::InnerDigest::default()));
        }
        Self { path }
    }
}

impl<P: SparseConfig> Default for MerkleSparseTreeTwoPaths<P> {
    fn default() -> Self {
        let mut path = Vec::with_capacity(P::HEIGHT as usize);
        for _i in 1..P::HEIGHT as usize {
            path.push(P::InnerDigest::default());
        }
        Self { path }
    }
}

impl<
        F: PrimeField + Absorb,
        P: SparseConfig<InnerDigest = F, LeafDigest = F, TwoToOneHash = TwoToOneCRH<F>>,
    > MerkleSparseTreePath<P>
{
    /// verify the lookup proof, just checking the membership
    pub fn verify(
        &self,
        leaf_hash_params: &<P::LeafHash as CRHScheme>::Parameters,
        two_to_one_hash_params: &<P::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
        root_hash: &P::InnerDigest,
        leaf: &P::Leaf,
    ) -> Result<bool, Error> {
        if self.path.len() != (P::HEIGHT - 1) as usize {
            return Ok(false);
        }
        // Check that the given leaf matches the leaf in the membership proof.
        if !self.path.is_empty() {
            let claimed_leaf_hash = P::LeafHash::evaluate(leaf_hash_params, leaf)?;

            if claimed_leaf_hash != self.path[0].0 && claimed_leaf_hash != self.path[0].1 {
                return Ok(false);
            }

            let mut prev = claimed_leaf_hash;
            // Check levels between leaf level and root.
            for (left_hash, right_hash) in &self.path {
                // Check if the previous hash matches the correct current hash.
                if &prev != left_hash && &prev != right_hash {
                    return Ok(false);
                }
                prev = P::TwoToOneHash::evaluate(two_to_one_hash_params, left_hash, right_hash)?;
            }

            if root_hash != &prev {
                return Ok(false);
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// verify the lookup proof, given the location
    pub fn verify_with_index(
        &self,
        leaf_hash_params: &<P::LeafHash as CRHScheme>::Parameters,
        two_to_one_hash_params: &<P::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
        root_hash: &P::InnerDigest,
        leaf: &P::Leaf,
        index: u64,
    ) -> Result<bool, Error> {
        if self.path.len() != (P::HEIGHT - 1) as usize {
            return Ok(false);
        }
        // Check that the given leaf matches the leaf in the membership proof.
        let last_level_index: u64 = (1u64 << (P::HEIGHT - 1)) - 1;
        let tree_index: u64 = last_level_index + index;

        let mut index_from_path: u64 = last_level_index;
        let mut index_offset: u64 = 1;

        if !self.path.is_empty() {
            let claimed_leaf_hash = P::LeafHash::evaluate(leaf_hash_params, leaf)?;

            if tree_index % 2 == 1 {
                if claimed_leaf_hash != self.path[0].0 {
                    return Ok(false);
                }
            } else if claimed_leaf_hash != self.path[0].1 {
                return Ok(false);
            }

            let mut prev = claimed_leaf_hash;
            let mut prev_index = tree_index;
            // Check levels between leaf level and root.
            for (left_hash, right_hash) in &self.path {
                // Check if the previous hash matches the correct current hash.
                if prev_index % 2 == 1 {
                    if &prev != left_hash {
                        return Ok(false);
                    }
                } else {
                    if &prev != right_hash {
                        return Ok(false);
                    }
                    index_from_path += index_offset;
                }
                index_offset *= 2;
                prev_index = (prev_index - 1) / 2;
                prev = P::TwoToOneHash::evaluate(two_to_one_hash_params, left_hash, right_hash)?;
            }

            if root_hash != &prev {
                return Ok(false);
            }

            if index_from_path != tree_index {
                return Ok(false);
            }

            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl<
        F: PrimeField + Absorb,
        P: SparseConfig<InnerDigest = F, LeafDigest = F, TwoToOneHash = TwoToOneCRH<F>>,
    > MerkleSparseTreeTwoPaths<P>
{
    /// verify the modifying proof
    pub fn verify(
        &self,
        leaf_hash_params: &<P::LeafHash as CRHScheme>::Parameters,
        two_to_one_hash_params: &<P::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
        old_root_hash: &P::InnerDigest,
        new_root_hash: &P::InnerDigest,
        old_leaf: &P::Leaf,
        new_leaf: &P::Leaf,
        index: u64,
    ) -> Result<bool, Error> {
        if self.path.len() != (P::HEIGHT - 1) as usize {
            return Ok(false);
        }
        // Check that the given leaf matches the leaf in the membership proof.
        let last_level_index: u64 = (1u64 << (P::HEIGHT - 1)) - 1;
        let mut tree_index: u64 = last_level_index + index;

        let mut old_hash = P::LeafHash::evaluate(leaf_hash_params, old_leaf)?;
        let mut new_hash = P::LeafHash::evaluate(leaf_hash_params, new_leaf)?;
        for neighbor in &self.path {
            (old_hash, new_hash) = if tree_index % 2 == 1 {
                (
                    P::TwoToOneHash::evaluate(two_to_one_hash_params, &old_hash, neighbor)?,
                    P::TwoToOneHash::evaluate(two_to_one_hash_params, &new_hash, neighbor)?,
                )
            } else {
                (
                    P::TwoToOneHash::evaluate(two_to_one_hash_params, neighbor, &old_hash)?,
                    P::TwoToOneHash::evaluate(two_to_one_hash_params, neighbor, &new_hash)?,
                )
            };
            tree_index = (tree_index - 1) / 2;
        }

        Ok(old_root_hash == &old_hash && new_root_hash == &new_hash && tree_index == 0)
    }
}

impl<
        F: PrimeField + Absorb,
        P: SparseConfig<InnerDigest = F, LeafDigest = F, TwoToOneHash = TwoToOneCRH<F>>,
    > MerkleSparseTree<P>
{
    /// obtain an empty tree
    pub fn blank(
        leaf_hash_params: &<P::LeafHash as CRHScheme>::Parameters,
        two_to_one_hash_params: &<P::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
    ) -> Self {
        let empty_hashes = gen_empty_hashes::<F, P>(
            leaf_hash_params,
            two_to_one_hash_params,
            &P::Leaf::default(),
            P::HEIGHT,
        )
        .unwrap();

        MerkleSparseTree {
            tree: BTreeMap::new(),
            leaf_hash_params: leaf_hash_params.clone(),
            two_to_one_hash_params: two_to_one_hash_params.clone(),
            root: Some(empty_hashes[(P::HEIGHT - 1) as usize]),
            empty_hashes,
        }
    }

    /// initialize a tree (with optional data)
    pub fn new(
        leaf_hash_params: &<P::LeafHash as CRHScheme>::Parameters,
        two_to_one_hash_params: &<P::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
        leaves: &BTreeMap<u64, P::Leaf>,
    ) -> Result<Self, Error> {
        let last_level_size = leaves.len().next_power_of_two();
        let tree_size = 2 * last_level_size - 1;
        let tree_height = tree_height(tree_size as u64);
        assert!(tree_height <= P::HEIGHT);

        // Initialize the merkle tree.
        let mut tree: BTreeMap<u64, P::InnerDigest> = BTreeMap::new();
        let empty_hashes = gen_empty_hashes::<F, P>(
            leaf_hash_params,
            two_to_one_hash_params,
            &P::Leaf::default(),
            P::HEIGHT,
        )?;

        // Compute and store the hash values for each leaf.
        let last_level_index: u64 = (1u64 << (P::HEIGHT - 1)) - 1;
        for (i, leaf) in leaves.iter() {
            tree.insert(
                last_level_index + *i,
                P::LeafHash::evaluate(leaf_hash_params, leaf)?,
            );
        }

        let mut middle_nodes: BTreeSet<u64> = BTreeSet::new();
        for i in leaves.keys() {
            middle_nodes.insert(parent(last_level_index + *i).unwrap());
        }

        // Compute the hash values for every node in parts of the tree.
        for level in 0..P::HEIGHT {
            // Iterate over the current level.
            for current_index in &middle_nodes {
                let left_index = left_child(*current_index);
                let right_index = right_child(*current_index);

                let mut left_hash = empty_hashes[level as usize];
                let mut right_hash = empty_hashes[level as usize];

                if tree.contains_key(&left_index) {
                    match tree.get(&left_index) {
                        Some(x) => left_hash = *x,
                        _ => {
                            return Err(Error::GenericError(Box::new(SparseMTError::GenericError)))
                        } // TODO: change this to smthing
                          // better
                    }
                }

                if tree.contains_key(&right_index) {
                    match tree.get(&right_index) {
                        Some(x) => right_hash = *x,
                        _ => {
                            return Err(Error::GenericError(Box::new(SparseMTError::GenericError)))
                        } // TODO:  change this to smthing better
                    }
                }

                // Compute Hash(left || right).
                tree.insert(
                    *current_index,
                    P::TwoToOneHash::evaluate(two_to_one_hash_params, &left_hash, &right_hash)?,
                );
            }

            let tmp_middle_nodes = middle_nodes.clone();
            middle_nodes.clear();
            for i in tmp_middle_nodes {
                if !is_root(i) {
                    middle_nodes.insert(parent(i).unwrap());
                }
            }
        }

        let root_hash = match tree.get(&0) {
            Some(x) => *x,
            _ => return Err(Error::GenericError(Box::new(SparseMTError::GenericError))), // TODO: change this to smthing better
        };

        Ok(MerkleSparseTree {
            tree,
            leaf_hash_params: leaf_hash_params.clone(),
            two_to_one_hash_params: two_to_one_hash_params.clone(),
            root: Some(root_hash),
            empty_hashes,
        })
    }

    #[inline]
    pub fn root(&self) -> P::InnerDigest {
        self.root.unwrap()
    }

    /// generate a membership proof (does not check the data point)
    pub fn generate_membership_proof(&self, index: u64) -> Result<MerkleSparseTreePath<P>, Error> {
        let mut path = Vec::new();

        let tree_height = P::HEIGHT;
        let tree_index = convert_index_to_last_level(index, tree_height);

        // Iterate from the leaf up to the root, storing all intermediate hash values.
        let mut current_node = tree_index;
        let mut empty_hashes_iter = self.empty_hashes.iter();
        while !is_root(current_node) {
            let sibling_node = sibling(current_node).unwrap();

            let mut current_hash = *empty_hashes_iter.next().unwrap();
            let mut sibling_hash = current_hash;

            if self.tree.contains_key(&current_node) {
                match self.tree.get(&current_node) {
                    Some(x) => current_hash = *x,
                    _ => return Err(Error::GenericError(Box::new(SparseMTError::GenericError))), // TODO: change this
                }
            }

            if self.tree.contains_key(&sibling_node) {
                match self.tree.get(&sibling_node) {
                    Some(x) => sibling_hash = *x,
                    _ => return Err(Error::GenericError(Box::new(SparseMTError::GenericError))), // TODO: change this
                }
            }

            if is_left_child(current_node) {
                path.push((current_hash, sibling_hash));
            } else {
                path.push((sibling_hash, current_hash));
            }
            current_node = parent(current_node).unwrap();
        }

        if path.len() != (P::HEIGHT - 1) as usize {
            Err(Error::GenericError(Box::new(SparseMTError::GenericError))) // TODO: change this
        } else {
            Ok(MerkleSparseTreePath { path })
        }
    }

    /// generate a lookup proof
    pub fn generate_proof(
        &self,
        index: u64,
        leaf: &P::Leaf,
    ) -> Result<MerkleSparseTreePath<P>, Error> {
        let leaf_hash = P::LeafHash::evaluate(&self.leaf_hash_params, leaf)?;
        let tree_height = P::HEIGHT;
        let tree_index = convert_index_to_last_level(index, tree_height);

        // Check that the given index corresponds to the correct leaf.
        if let Some(x) = self.tree.get(&tree_index) {
            if leaf_hash != *x {
                return Err(Error::GenericError(Box::new(SparseMTError::GenericError)));
                // TODO: change this
            }
        }

        self.generate_membership_proof(index)
    }

    /// update the tree and provide a modifying proof
    pub fn update_and_prove(
        &mut self,
        index: u64,
        new_leaf: &P::Leaf,
    ) -> Result<MerkleSparseTreeTwoPaths<P>, Error> {
        let siblings = self.siblings(index)?;

        let mut hash = P::LeafHash::evaluate(&self.leaf_hash_params, new_leaf)?;
        let mut index = convert_index_to_last_level(index, P::HEIGHT);

        for sibling in &siblings {
            self.tree.insert(index, hash);
            hash = if is_left_child(index) {
                P::TwoToOneHash::evaluate(&self.two_to_one_hash_params, &hash, sibling)?
            } else {
                P::TwoToOneHash::evaluate(&self.two_to_one_hash_params, sibling, &hash)?
            };
            index = parent(index).unwrap();
        }
        self.tree.insert(0, hash);
        self.root = Some(hash);

        Ok(MerkleSparseTreeTwoPaths { path: siblings })
    }

    pub fn siblings(&mut self, index: u64) -> Result<Vec<F>, Error> {
        let mut siblings = vec![];

        let tree_height = P::HEIGHT;
        let mut index = convert_index_to_last_level(index, tree_height);

        for i in 0..tree_height - 1 {
            siblings.push(
                *self
                    .tree
                    .get(&sibling(index).unwrap())
                    .unwrap_or(&self.empty_hashes[i as usize]),
            );
            index = parent(index).unwrap();
        }

        Ok(siblings)
    }

    /// check if the tree is structurally valid
    pub fn validate(&self) -> Result<bool, Error> {
        /* Finding the leaf nodes */
        let last_level_index: u64 = (1u64 << (P::HEIGHT - 1)) - 1;
        let mut middle_nodes: BTreeSet<u64> = BTreeSet::new();

        for key in self.tree.keys() {
            if *key >= last_level_index && !is_root(*key) {
                middle_nodes.insert(parent(*key).unwrap());
            }
        }

        for level in 0..P::HEIGHT {
            for current_index in &middle_nodes {
                let left_index = left_child(*current_index);
                let right_index = right_child(*current_index);

                let mut left_hash = self.empty_hashes[level as usize];
                let mut right_hash = self.empty_hashes[level as usize];

                if self.tree.contains_key(&left_index) {
                    match self.tree.get(&left_index) {
                        Some(x) => left_hash = *x,
                        _ => {
                            return Ok(false);
                        }
                    }
                }

                if self.tree.contains_key(&right_index) {
                    match self.tree.get(&right_index) {
                        Some(x) => right_hash = *x,
                        _ => {
                            return Ok(false);
                        }
                    }
                }

                let hash = P::TwoToOneHash::evaluate(
                    &self.two_to_one_hash_params,
                    &left_hash,
                    &right_hash,
                )?;

                match self.tree.get(current_index) {
                    Some(x) => {
                        if *x != hash {
                            return Ok(false);
                        }
                    }
                    _ => {
                        return Ok(false);
                    }
                }
            }

            let tmp_middle_nodes = middle_nodes.clone();
            middle_nodes.clear();
            for i in tmp_middle_nodes {
                if !is_root(i) {
                    middle_nodes.insert(parent(i).unwrap());
                }
            }
        }

        Ok(true)
    }
}

/// Returns the log2 value of the given number.
#[inline]
fn log2(number: u64) -> u64 {
    ark_std::log2(number as usize) as u64
}

/// Returns the height of the tree, given the size of the tree.
#[inline]
fn tree_height(tree_size: u64) -> u64 {
    log2(tree_size)
}

/// Returns true iff the index represents the root.
#[inline]
fn is_root(index: u64) -> bool {
    index == 0
}

/// Returns the index of the left child, given an index.
#[inline]
fn left_child(index: u64) -> u64 {
    2 * index + 1
}

/// Returns the index of the right child, given an index.
#[inline]
fn right_child(index: u64) -> u64 {
    2 * index + 2
}

/// Returns the index of the sibling, given an index.
#[inline]
fn sibling(index: u64) -> Option<u64> {
    if index == 0 {
        None
    } else if is_left_child(index) {
        Some(index + 1)
    } else {
        Some(index - 1)
    }
}

/// Returns true iff the given index represents a left child.
#[inline]
fn is_left_child(index: u64) -> bool {
    index % 2 == 1
}

/// Returns the index of the parent, given an index.
#[inline]
fn parent(index: u64) -> Option<u64> {
    if index > 0 {
        Some((index - 1) >> 1)
    } else {
        None
    }
}

#[inline]
fn convert_index_to_last_level(index: u64, tree_height: u64) -> u64 {
    index + (1 << (tree_height - 1)) - 1
}

fn gen_empty_hashes<
    F: PrimeField + Absorb,
    P: SparseConfig<InnerDigest = F, LeafDigest = F, TwoToOneHash = TwoToOneCRH<F>>,
>(
    leaf_hash_params: &<P::LeafHash as CRHScheme>::Parameters,
    two_to_one_hash_params: &<P::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
    empty_leaf: &P::Leaf,
    n: u64,
) -> Result<Vec<P::InnerDigest>, Error> {
    let mut empty_hashes = Vec::with_capacity(n as usize);
    let mut empty_hash = P::LeafHash::evaluate(leaf_hash_params, empty_leaf)?;
    empty_hashes.push(empty_hash);

    for _ in 1..=n {
        empty_hash = <P::TwoToOneHash as TwoToOneCRHScheme>::evaluate(
            two_to_one_hash_params,
            empty_hash,
            empty_hash,
        )?;
        empty_hashes.push(empty_hash);
    }

    Ok(empty_hashes)
}

#[cfg(test)]
mod test {
    use crate::datastructures::{
        keypair::PublicKey,
        utxo::{UTXOTreeConfig, UTXO},
    };

    use super::*;

    use ark_bn254::Fr;
    use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
    use ark_ff::Zero;
    use ark_grumpkin::Projective;
    use ark_std::collections::BTreeMap;
    use folding_schemes::transcript::poseidon::poseidon_canonical_config;

    type UTXOMerkleTree = MerkleSparseTree<UTXOTreeConfig<Projective>>;

    fn generate_merkle_tree_and_test_membership(
        leaf_hash_params: &PoseidonConfig<Fr>,
        two_to_one_hash_params: &PoseidonConfig<Fr>,
        leaves: &BTreeMap<u64, UTXO<Projective>>,
    ) {
        let tree = UTXOMerkleTree::new(leaf_hash_params, two_to_one_hash_params, leaves).unwrap();
        let root = tree.root();
        for (i, leaf) in leaves.iter() {
            let proof = tree.generate_proof(*i, leaf).unwrap();
            assert!(proof
                .verify(leaf_hash_params, two_to_one_hash_params, &root, leaf)
                .unwrap());
            assert!(proof
                .verify_with_index(leaf_hash_params, two_to_one_hash_params, &root, leaf, *i)
                .unwrap());
        }

        assert!(tree.validate().unwrap());
    }

    #[test]
    fn good_root_membership_test() {
        let pp = poseidon_canonical_config();
        let mut leaves: BTreeMap<u64, UTXO<Projective>> = BTreeMap::new();
        for i in 1..10u8 {
            leaves.insert(i as u64, UTXO::new(PublicKey::default(), i.into()));
        }
        generate_merkle_tree_and_test_membership(&pp, &pp, &leaves);
        let mut leaves: BTreeMap<u64, UTXO<Projective>> = BTreeMap::new();
        for i in 1..100u8 {
            leaves.insert(
                i as u64,
                UTXO::<Projective>::new(PublicKey::default(), i.into()),
            );
        }
        generate_merkle_tree_and_test_membership(&pp, &pp, &leaves);
    }

    fn generate_merkle_tree_with_bad_root_and_test_membership(
        leaf_hash_params: &PoseidonConfig<Fr>,
        two_to_one_hash_params: &PoseidonConfig<Fr>,
        leaves: &BTreeMap<u64, UTXO<Projective>>,
    ) {
        let tree = UTXOMerkleTree::new(leaf_hash_params, two_to_one_hash_params, leaves).unwrap();
        let root = Fr::zero();
        for (i, leaf) in leaves.iter() {
            let proof = tree.generate_proof(*i, leaf).unwrap();
            assert!(proof
                .verify(leaf_hash_params, two_to_one_hash_params, &root, leaf)
                .unwrap());
            assert!(proof
                .verify_with_index(leaf_hash_params, two_to_one_hash_params, &root, leaf, *i)
                .unwrap());
        }
    }

    #[should_panic]
    #[test]
    fn bad_root_membership_test() {
        let pp = poseidon_canonical_config::<Fr>();
        let mut leaves: BTreeMap<u64, UTXO<Projective>> = BTreeMap::new();
        for i in 1..100u8 {
            leaves.insert(i as u64, UTXO::new(PublicKey::default(), i.into()));
        }
        generate_merkle_tree_with_bad_root_and_test_membership(&pp, &pp, &leaves);
    }

    fn generate_merkle_tree_and_test_update(
        leaf_hash_params: &PoseidonConfig<Fr>,
        two_to_one_hash_params: &PoseidonConfig<Fr>,
        old_leaves: &BTreeMap<u64, UTXO<Projective>>,
        new_leaves: &BTreeMap<u64, UTXO<Projective>>,
    ) {
        let mut tree =
            UTXOMerkleTree::new(leaf_hash_params, two_to_one_hash_params, old_leaves).unwrap();
        for (i, new_leaf) in new_leaves.iter() {
            let old_root = tree.root.unwrap();
            let old_leaf_option = old_leaves.get(i);

            match old_leaf_option {
                Some(old_leaf) => {
                    let old_leaf_membership_proof = tree.generate_proof(*i, old_leaf).unwrap();
                    let update_proof = tree.update_and_prove(*i, new_leaf).unwrap();
                    let new_leaf_membership_proof = tree.generate_proof(*i, new_leaf).unwrap();
                    let new_root = tree.root.unwrap();

                    assert!(old_leaf_membership_proof
                        .verify_with_index(
                            leaf_hash_params,
                            two_to_one_hash_params,
                            &old_root,
                            old_leaf,
                            *i
                        )
                        .unwrap());
                    assert!(
                        !(old_leaf_membership_proof
                            .verify_with_index(
                                leaf_hash_params,
                                two_to_one_hash_params,
                                &new_root,
                                old_leaf,
                                *i
                            )
                            .unwrap())
                    );
                    assert!(new_leaf_membership_proof
                        .verify_with_index(
                            leaf_hash_params,
                            two_to_one_hash_params,
                            &new_root,
                            new_leaf,
                            *i
                        )
                        .unwrap());
                    assert!(
                        !(new_leaf_membership_proof
                            .verify_with_index(
                                leaf_hash_params,
                                two_to_one_hash_params,
                                &new_root,
                                old_leaf,
                                *i
                            )
                            .unwrap())
                    );

                    assert!(update_proof
                        .verify(
                            leaf_hash_params,
                            two_to_one_hash_params,
                            &old_root,
                            &new_root,
                            old_leaf,
                            new_leaf,
                            *i
                        )
                        .unwrap());
                }
                None => {
                    let update_proof = tree.update_and_prove(*i, new_leaf).unwrap();
                    let new_leaf_membership_proof = tree.generate_proof(*i, new_leaf).unwrap();
                    let new_root = tree.root.unwrap();

                    assert!(new_leaf_membership_proof
                        .verify_with_index(
                            leaf_hash_params,
                            two_to_one_hash_params,
                            &new_root,
                            new_leaf,
                            *i
                        )
                        .unwrap());
                    assert!(update_proof
                        .verify(
                            leaf_hash_params,
                            two_to_one_hash_params,
                            &old_root,
                            &new_root,
                            &UTXO::default(),
                            new_leaf,
                            *i
                        )
                        .unwrap());
                }
            }
        }
    }

    #[test]
    fn good_root_update_test() {
        let pp = poseidon_canonical_config::<Fr>();
        let mut old_leaves: BTreeMap<u64, UTXO<Projective>> = BTreeMap::new();
        for i in 1..10u8 {
            old_leaves.insert(i as u64, UTXO::new(PublicKey::default(), i.into()));
        }
        let mut new_leaves: BTreeMap<u64, UTXO<Projective>> = BTreeMap::new();
        for i in 1..20u8 {
            new_leaves.insert(i as u64, UTXO::new(PublicKey::default(), (i * 3).into()));
        }
        generate_merkle_tree_and_test_update(&pp, &pp, &old_leaves, &new_leaves);
    }
}
