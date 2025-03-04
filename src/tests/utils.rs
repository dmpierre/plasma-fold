use crate::circuits::{
    asset_tree::{self, AssetTree, ASSET_TREE_N_TOKENS},
    block::Block,
    deposit::Deposit,
    PlasmaFoldExternalInputs, PlasmaFoldExternalInputsVar,
};
use ark_crypto_primitives::{
    crh::{CRHScheme, TwoToOneCRHScheme},
    merkle_tree::{constraints::ConfigGadget, Config, MerkleTree},
    sponge::Absorb,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::r1cs::ConstraintSystemRef;

/// Inits
/// For testing purposes
pub fn init_external_inputs<P: Config<Leaf = [F]>, F: PrimeField + Absorb>(
    salt: F, // required to compute the public state
    block: Option<Block<P>>,
    deposit: Option<Deposit<P, F>>,
) -> PlasmaFoldExternalInputs<P, F> {
    let mut external_inputs = PlasmaFoldExternalInputs::default();
    external_inputs.salt = salt;
    if let Some(b) = block {
        external_inputs.block = b;
    }
    if let Some(d) = deposit {
        external_inputs.deposit = d;
    }
    // let (z_i_vars, external_inputs_vars) = initialize_vars(cs.clone(), z_i, &external_inputs);
    external_inputs
}

/// Initialize relevant constraint inputs for the plasma fold circuit. Returns the initialized
/// variables and IVC state vector variable
pub fn init_vars<P: Config, F: PrimeField + Absorb, PG: ConfigGadget<P, F>>(
    cs: ConstraintSystemRef<F>,
    z_i: &[F],
    external_inputs: &PlasmaFoldExternalInputs<P, F>,
) -> (Vec<FpVar<F>>, PlasmaFoldExternalInputsVar<P, F, PG>) {
    let z_i = Vec::<FpVar<F>>::new_witness(cs.clone(), || Ok(Vec::from(z_i))).unwrap();
    let external_inputs_var =
        PlasmaFoldExternalInputsVar::<P, F, PG>::new_witness(cs.clone(), || Ok(external_inputs))
            .unwrap();
    (z_i, external_inputs_var)
}

/// Get a deposit, `deposit_flag` specifies what the value for the deposit_flag field should be
/// `deposit_valid` specifies whether the deposit proof should be valid or not
pub fn get_deposit<P: Config<Leaf = [F]>, F: PrimeField>(
    leaf_hash_config: &<<P as Config>::LeafHash as CRHScheme>::Parameters,
    two_to_one_hash_config: &<<P as Config>::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
    deposit_flag: bool,
    deposit_valid: bool,
) -> (MerkleTree<P>, Deposit<P, F>) {
    // leaves of the deposit tree
    let mut leaves = [[F::from(0), F::from(123)], [F::from(1), F::from(456)]];
    let deposit_tree = MerkleTree::new(leaf_hash_config, two_to_one_hash_config, leaves).unwrap();
    let deposit_proof = deposit_tree.generate_proof(0).unwrap();

    // we change leaves in the case where we want an invalid deposit
    if !deposit_valid {
        leaves[0] = [F::from(0), F::from(0)];
    }

    // initialize deposit
    let deposit = Deposit {
        path: deposit_proof,
        root: deposit_tree.root(),
        value: leaves[0],
        flag: deposit_flag,
    };

    (deposit_tree, deposit)
}

/// Get an asset tree
pub fn get_asset_tree<P: Config<Leaf = [F]>, F: PrimeField>(
    leaf_hash_config: &<<P as Config>::LeafHash as CRHScheme>::Parameters,
    two_to_one_hash_config: &<<P as Config>::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
) -> (AssetTree<P>, MerkleTree<P>, [[F; 1]; ASSET_TREE_N_TOKENS]) {
    // leaves of the asset tree, all initialized at zero
    let mut leaves = [[F::ZERO; 1]; ASSET_TREE_N_TOKENS];
    leaves[1] = [F::from(10)];
    let tree = MerkleTree::new(leaf_hash_config, two_to_one_hash_config, leaves).unwrap();
    let asset_tree = AssetTree { root: tree.root() };
    (asset_tree, tree, leaves)
}
