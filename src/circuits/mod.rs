use std::{borrow::Borrow, marker::PhantomData};

use ark_crypto_primitives::{
    crh::{CRHScheme, CRHSchemeGadget, TwoToOneCRHScheme, TwoToOneCRHSchemeGadget},
    merkle_tree::{constraints::ConfigGadget, Config},
    sponge::Absorb,
    Error,
};

use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::fp::FpVar,
    prelude::{ToBitsGadget, ToBytesGadget},
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use asset_tree::{
    AssetTree, AssetTreeVar, ProofAssetTreeUpdateFromDeposit, ProofAssetTreeUpdateFromDepositVar,
};
use block::{Block, BlockVar};
use deposit::{Deposit, DepositVar};
use folding_schemes::frontend::FCircuit;

pub mod asset_tree;
pub mod block;
pub mod deposit;

/// PlasmaFold external inputs are inputs kept private by the plasma chain user. They consist into
/// all necessary inputs for performing various actions on the plasma chain.
#[derive(Debug, Clone)]
pub struct PlasmaFoldExternalInputs<P: Config, F: PrimeField> {
    pub salt: F, // salt ensuring privacy of the user's balance
    // deposit witness (merkle proof of inclusion within the deposit block)
    pub deposit: Deposit<P, F>,
    // block, containing different trees
    pub block: Block<P>,
    // user's asset tree on the plasma chain
    pub asset_tree: AssetTree<P>,
    // a proof that updates the asset tree from a deposit
    pub proof_asset_tree_update_from_deposit: ProofAssetTreeUpdateFromDeposit<P, F>,
}

impl<P: Config<Leaf = [F], LeafDigest = F, InnerDigest = F>, F: PrimeField>
    PlasmaFoldExternalInputs<P, F>
{
    pub fn compute_public_state(
        &self,
        params: &<<P as Config>::LeafHash as CRHScheme>::Parameters,
    ) -> Result<F, Error> {
        return <<P as Config>::LeafHash as CRHScheme>::evaluate(
            &params,
            [self.salt, self.asset_tree.root],
        );
    }
}

#[derive(Debug, Clone)]
pub struct PlasmaFoldExternalInputsVar<P: Config, F: PrimeField + Absorb, PG: ConfigGadget<P, F>> {
    pub salt: FpVar<F>,
    pub deposit_var: DepositVar<P, F, PG>,
    pub block_var: BlockVar<P, F, PG>,
    pub asset_tree_var: AssetTreeVar<P, F, PG>,
    pub proof_asset_tree_update_from_deposit: ProofAssetTreeUpdateFromDepositVar<P, F, PG>,
}

#[derive(Clone, Debug)]
pub struct PlasmaFoldCircuit<P: Config, F: PrimeField + Absorb, PG: ConfigGadget<P, F>> {
    mt_config: P,
    _f: PhantomData<F>,
    _f1: PhantomData<P>,
    _f2: PhantomData<PG>,
}

impl<P: Config, F: PrimeField + Absorb, PG: ConfigGadget<P, F>>
    AllocVar<PlasmaFoldExternalInputs<P, F>, F> for PlasmaFoldExternalInputsVar<P, F, PG>
{
    // TODO: the deposit root is duplicated, remove this duplication
    fn new_variable<T: Borrow<PlasmaFoldExternalInputs<P, F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        f().and_then(|val| {
            let external_inputs: &PlasmaFoldExternalInputs<P, F> = val.borrow();
            let salt = FpVar::<F>::new_witness(ark_relations::ns!(cs, "salt"), || {
                Ok(external_inputs.salt)
            })?;
            let deposit_var = DepositVar::new_witness(ark_relations::ns!(cs, "deposit"), || {
                Ok(&external_inputs.deposit)
            })?;
            let block_var = BlockVar::new_witness(ark_relations::ns!(cs, "block"), || {
                Ok(&external_inputs.block)
            })?;
            let asset_tree_var =
                AssetTreeVar::new_witness(ark_relations::ns!(cs, "asset_tree"), || {
                    Ok(&external_inputs.asset_tree)
                })?;
            let proof_asset_tree_update_from_deposit =
                ProofAssetTreeUpdateFromDepositVar::new_witness(
                    ark_relations::ns!(cs, "proof_asset_tree_update_from_deposit"),
                    || Ok(&external_inputs.proof_asset_tree_update_from_deposit),
                )?;
            Ok(PlasmaFoldExternalInputsVar {
                salt,
                block_var,
                deposit_var,
                asset_tree_var,
                proof_asset_tree_update_from_deposit,
            })
        })
    }
}

/// The `PlasmaFoldExternalInputsVar` struct implements methods to check various actions the user can take on the
/// plasma chain: deposit, transfer, receive, withdraw
/// For now, it uses the same hash for both computing merkle trees and block hashes
/// TODO: be generic over the CRH used as well
impl<
        P: Config,
        F: PrimeField + Absorb,
        PG: ConfigGadget<P, F, Leaf = [FpVar<F>], InnerDigest = FpVar<F>, LeafDigest = FpVar<F>>,
    > PlasmaFoldExternalInputsVar<P, F, PG>
where
    P: Borrow<<<P as Config>::LeafHash as CRHScheme>::Parameters>
        + Borrow<<<P as Config>::TwoToOneHash as TwoToOneCRHScheme>::Parameters>
        + Clone,
{
    /// Compute block hash
    pub fn compute_block_hash(
        &self,
        cs: ConstraintSystemRef<F>,
        config: P,
        prev_block_hash: &FpVar<F>,
    ) -> Result<<PG::LeafHash as CRHSchemeGadget<P::LeafHash, F>>::OutputVar, SynthesisError> {
        let crh_parameters_var = <<PG as ConfigGadget<P, F>>::LeafHash as CRHSchemeGadget<
            <P as Config>::LeafHash,
            F,
        >>::ParametersVar::new_constant(
            ark_relations::ns!(cs, "crh_params"), config.clone()
        )?;
        <PG::LeafHash as CRHSchemeGadget<P::LeafHash, F>>::evaluate(
            &crh_parameters_var,
            &[
                prev_block_hash.clone(),
                self.block_var.deposit_tree_root.clone(),
                self.block_var.transaction_tree_root.clone(),
                self.block_var.withdrawal_tree_root.clone(),
            ],
        )
    }

    /// Checking the deposit consists in checking a merkle inclusion proof within a deposit block
    pub fn deposit(
        &mut self,
        cs: ConstraintSystemRef<F>,
        config: P,
    ) -> Result<FpVar<F>, SynthesisError> {
        let leaf_crh_params_var = <<PG as ConfigGadget<P, F>>::LeafHash as CRHSchemeGadget<
            <P as Config>::LeafHash,
            F,
        >>::ParametersVar::new_constant(
            ark_relations::ns!(cs, "leaf_crh_params"), config.clone()
        )?;

        let two_to_one_crh_params_var =
            <<PG as ConfigGadget<P, F>>::TwoToOneHash as TwoToOneCRHSchemeGadget<
                <P as Config>::TwoToOneHash,
                F,
            >>::ParametersVar::new_constant(
                ark_relations::ns!(cs, "two_to_one_crh_parameter"),
                config.clone(),
            )?;

        // Check that the deposit is present in the deposit tree
        let deposit_is_ok = self.deposit_var.path.verify_membership(
            &leaf_crh_params_var,
            &two_to_one_crh_params_var,
            &self.block_var.deposit_tree_root,
            &self.deposit_var.value,
        )?;
        // ensure that deposit_is_ok == deposit_flag
        // (i.e. we can't have a correct deposit with flag set to false)
        let deposit_flag = &self.deposit_var.flag;
        deposit_is_ok.enforce_equal(deposit_flag)?;

        // Ensure that deposit amount is not negative
        // When the flag is false, the asset tree is untouched
        let deposit_flag_as_fp_var = deposit_flag.to_bytes_le()?[0].to_fp()?;
        let deposit_amount = deposit_flag_as_fp_var * &self.deposit_var.value[1];
        deposit_amount.enforce_smaller_or_equal_than_mod_minus_one_div_two()?;

        // make sure the the token index is the one that will be used to update the asset tree
        // we set the path to the index that we will update
        let token_index = self.deposit_var.value[0].to_bits_le()?;
        self.proof_asset_tree_update_from_deposit
            .prev_value_path
            .set_leaf_position(token_index);

        // Update the asset tree root with the deposit
        let new_leaf_value =
            &self.proof_asset_tree_update_from_deposit.prev_value[0] + &deposit_amount;
        let new_asset_tree_root = self
            .proof_asset_tree_update_from_deposit
            .prev_value_path
            .update_leaf(
                &leaf_crh_params_var,
                &two_to_one_crh_params_var,
                &self.proof_asset_tree_update_from_deposit.prev_root,
                &self.proof_asset_tree_update_from_deposit.prev_value,
                &[new_leaf_value],
            )?;

        // Return the updated asset tree root
        Ok(new_asset_tree_root)
    }

    pub fn compute_public_state(
        &self,
        cs: ConstraintSystemRef<F>,
        config: P,
    ) -> Result<FpVar<F>, SynthesisError> {
        let crh_params_var = <<PG as ConfigGadget<P, F>>::LeafHash as CRHSchemeGadget<
            <P as Config>::LeafHash,
            F,
        >>::ParametersVar::new_constant(
            ark_relations::ns!(cs, "crh_params"), config.clone()
        )?;

        PG::LeafHash::evaluate(
            &crh_params_var,
            &[self.salt.clone(), self.asset_tree_var.root.clone()],
        )
    }

    pub fn update_public_state(
        &self,
        cs: ConstraintSystemRef<F>,
        config: P,
        asset_tree_root: FpVar<F>,
    ) -> Result<FpVar<F>, SynthesisError> {
        let crh_params_var = <<PG as ConfigGadget<P, F>>::LeafHash as CRHSchemeGadget<
            <P as Config>::LeafHash,
            F,
        >>::ParametersVar::new_constant(
            ark_relations::ns!(cs, "crh_params"), config.clone()
        )?;

        PG::LeafHash::evaluate(
            &crh_params_var,
            &[self.salt.clone(), asset_tree_root.clone()],
        )
    }
}

impl<P: Config, F: PrimeField> Default for PlasmaFoldExternalInputs<P, F> {
    fn default() -> Self {
        PlasmaFoldExternalInputs {
            salt: F::default(),
            deposit: Deposit::default(),
            block: Block::default(),
            asset_tree: AssetTree::default(),
            proof_asset_tree_update_from_deposit: ProofAssetTreeUpdateFromDeposit::default(),
        }
    }
}

impl<
        P: Config + Clone + std::fmt::Debug, // for computing trees
        F: PrimeField + Absorb,
        PG: ConfigGadget<P, F, Leaf = [FpVar<F>], InnerDigest = FpVar<F>, LeafDigest = FpVar<F>>
            + Clone
            + std::fmt::Debug,
    > FCircuit<F> for PlasmaFoldCircuit<P, F, PG>
where
    P: Borrow<<<P as Config>::LeafHash as CRHScheme>::Parameters>
        + Borrow<<<P as Config>::TwoToOneHash as TwoToOneCRHScheme>::Parameters>
        + Clone,
{
    type Params = P;

    type ExternalInputs = PlasmaFoldExternalInputs<P, F>;

    type ExternalInputsVar = PlasmaFoldExternalInputsVar<P, F, PG>;

    fn new(params: Self::Params) -> Result<Self, folding_schemes::Error> {
        Ok(Self {
            mt_config: params,
            _f: PhantomData::<F>,
            _f1: PhantomData::<P>,
            _f2: PhantomData::<PG>,
        })
    }

    /// the IVC state consists in `[prev_block_hash, nonce, h(asset_tree_root, salt)]` and indicate whether the account is up to
    /// date with the latest block and the rollup contract stored nonce.
    fn state_len(&self) -> usize {
        3
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        i: usize,
        z_i: Vec<FpVar<F>>,
        mut external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // VALIDATE INPUTS
        // - Check that h(asset_tree_root, salt) == z_i[2]
        let computed_public_state =
            external_inputs.compute_public_state(cs.clone(), self.mt_config.clone())?;
        computed_public_state.enforce_equal(&z_i[2])?;

        // DEPOSIT
        let new_asset_tree_root = external_inputs.deposit(cs.clone(), self.mt_config.clone())?;

        // TRANSFER
        // 1. Check that transfer tree is correct
        //

        // 2. Update balance
        //
        //

        // 3. Update nonce

        // RECEIVE TRANSFER

        // WITHDRAW
        //

        // COMPUTE NEXT BLOCK HASH
        let new_block_hash = external_inputs.compute_block_hash(
            cs.clone(),
            // for now, we are using the same CRH as the one used for our merkle trees
            self.mt_config.clone(),
            &z_i[0].clone(),
        )?;

        // COMPUTE NEW PUBLIC STATE
        let new_public_state = external_inputs.update_public_state(
            cs.clone(),
            self.mt_config.clone(),
            new_asset_tree_root,
        )?;

        Ok(Vec::from([
            new_block_hash,
            z_i[1].clone(),
            new_public_state.clone(),
        ]))
    }
}

pub mod tests {

    use ark_bn254::fr::Fr;
    use ark_crypto_primitives::{
        crh::poseidon::{
            constraints::{CRHGadget, TwoToOneCRHGadget},
            TwoToOneCRH, CRH,
        },
        merkle_tree::{constraints::ConfigGadget, Config, IdentityDigestConverter},
        sponge::poseidon::PoseidonConfig,
    };
    use ark_ff::{AdditiveGroup, Field, PrimeField};
    use ark_r1cs_std::{fields::fp::FpVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;
    use folding_schemes::{frontend::FCircuit, transcript::poseidon::poseidon_canonical_config};
    use std::{borrow::Borrow, task::Wake};

    use crate::tests::utils::{get_asset_tree, get_deposit, init_external_inputs, init_vars};

    use crate::circuits::PlasmaFoldCircuit;

    use super::{
        asset_tree::{AssetTree, ProofAssetTreeUpdateFromDeposit},
        block::Block,
        PlasmaFoldExternalInputs,
    };

    impl Borrow<PoseidonConfig<Fr>> for FieldMTConfig {
        fn borrow(&self) -> &PoseidonConfig<Fr> {
            return self.poseidon_conf.borrow();
        }
    }

    #[derive(Debug, Clone)]
    pub struct FieldMTConfig {
        poseidon_conf: PoseidonConfig<Fr>,
    }
    impl Config for FieldMTConfig {
        type Leaf = [Fr];
        type LeafDigest = Fr;
        type LeafInnerDigestConverter = IdentityDigestConverter<Fr>;
        type InnerDigest = Fr;
        type LeafHash = CRH<Fr>;
        type TwoToOneHash = TwoToOneCRH<Fr>;
    }

    #[derive(Debug, Clone)]
    pub struct FieldMTConfigVar;
    impl ConfigGadget<FieldMTConfig, Fr> for FieldMTConfigVar {
        type Leaf = [FpVar<Fr>];
        type LeafDigest = FpVar<Fr>;
        type LeafInnerConverter = IdentityDigestConverter<FpVar<Fr>>;
        type InnerDigest = FpVar<Fr>;
        type LeafHash = CRHGadget<Fr>;
        type TwoToOneHash = TwoToOneCRHGadget<Fr>;
    }

    pub fn test_asset_tree_is_not_updated_with_wrong_deposit() -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let poseidon_config = poseidon_canonical_config::<Fr>();
        let (salt, balance) = (Fr::ONE, Fr::ONE);
        let (prev_block_hash, nonce) = (Fr::ONE, Fr::ONE);
        let (deposit_tree, mut deposit) =
            get_deposit::<FieldMTConfig, Fr>(&poseidon_config, &poseidon_config, true, true);
        let block: Block<FieldMTConfig> = Block {
            transaction_tree_root: Fr::ZERO,
            deposit_tree_root: Fr::ZERO, // change the deposit root, deposit proof is invalid
            withdrawal_tree_root: Fr::ZERO,
        };
        // set the flag to false, to not update the asset tree
        deposit.flag = false;
        let (asset_tree, asset_merkle_tree, leaves) =
            get_asset_tree::<FieldMTConfig, Fr>(&poseidon_config, &poseidon_config);

        let proof_asset_tree_update_from_deposit = ProofAssetTreeUpdateFromDeposit {
            prev_value_path: asset_merkle_tree.generate_proof(0).unwrap(), // merkle path in asset tree attesting to leaf value
            prev_value: leaves[0],      // prev leaf value in asset tree
            prev_root: asset_tree.root, // prev assset tree root
        };

        let external_inputs = PlasmaFoldExternalInputs {
            salt,
            deposit,
            block,
            asset_tree,
            proof_asset_tree_update_from_deposit,
        };
        let z_i = [
            prev_block_hash,
            nonce,
            external_inputs
                .compute_public_state(&poseidon_config)
                .unwrap(),
        ];

        let (z_i_vars, external_inputs_vars) = init_vars(cs.clone(), &z_i, &external_inputs);

        let field_mt_config = FieldMTConfig {
            poseidon_conf: poseidon_config,
        };
        let plasma_fold_circuit =
            PlasmaFoldCircuit::<FieldMTConfig, Fr, FieldMTConfigVar>::new(field_mt_config).unwrap();

        let z_i_1 = plasma_fold_circuit
            .generate_step_constraints(cs.clone(), 0, z_i_vars.clone(), external_inputs_vars)
            .unwrap();

        let is_satisfied = cs.is_satisfied().unwrap();
        assert!(is_satisfied);
        assert_eq!(z_i_1[2].value(), z_i_vars[2].value());
        is_satisfied
    }

    pub fn test_plasmafold_circuit() -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let poseidon_config = poseidon_canonical_config::<Fr>();
        let (salt, balance) = (Fr::ONE, Fr::ONE);
        let (prev_block_hash, nonce) = (Fr::ONE, Fr::ONE);
        let (deposit_tree, deposit) =
            get_deposit::<FieldMTConfig, Fr>(&poseidon_config, &poseidon_config, true, true);
        let block: Block<FieldMTConfig> = Block {
            transaction_tree_root: Fr::ZERO,
            deposit_tree_root: deposit_tree.root(),
            withdrawal_tree_root: Fr::ZERO,
        };
        let (asset_tree, asset_merkle_tree, leaves) =
            get_asset_tree::<FieldMTConfig, Fr>(&poseidon_config, &poseidon_config);

        let proof_asset_tree_update_from_deposit = ProofAssetTreeUpdateFromDeposit {
            prev_value_path: asset_merkle_tree.generate_proof(0).unwrap(), // merkle path in asset tree attesting to leaf value
            prev_value: leaves[0],      // prev leaf value in asset tree
            prev_root: asset_tree.root, // prev assset tree root
        };

        let external_inputs = PlasmaFoldExternalInputs {
            salt,
            deposit,
            block,
            asset_tree,
            proof_asset_tree_update_from_deposit,
        };
        let z_i = [
            prev_block_hash,
            nonce,
            external_inputs
                .compute_public_state(&poseidon_config)
                .unwrap(),
        ];

        let (z_i_vars, external_inputs_vars) = init_vars(cs.clone(), &z_i, &external_inputs);

        let field_mt_config = FieldMTConfig {
            poseidon_conf: poseidon_config,
        };
        let plasma_fold_circuit =
            PlasmaFoldCircuit::<FieldMTConfig, Fr, FieldMTConfigVar>::new(field_mt_config).unwrap();

        let z_i_1 = plasma_fold_circuit
            .generate_step_constraints(cs.clone(), 0, z_i_vars.clone(), external_inputs_vars)
            .unwrap();

        let is_satisfied = cs.is_satisfied().unwrap();
        assert!(is_satisfied);

        // ensure that asset tree is updated
        assert_ne!(z_i_1[2].value(), z_i_vars[2].value());
        is_satisfied
    }
}
