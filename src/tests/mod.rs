pub mod tests {
    use ark_bn254::fr::Fr;
    use ark_crypto_primitives::{
        crh::{
            poseidon::{
                constraints::{CRHGadget, TwoToOneCRHGadget},
                TwoToOneCRH, CRH,
            },
            CRHScheme, TwoToOneCRHScheme,
        },
        merkle_tree::{constraints::ConfigGadget, Config, IdentityDigestConverter, MerkleTree},
        sponge::poseidon::PoseidonConfig,
    };
    use ark_ff::Zero;
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
    use folding_schemes::{frontend::FCircuit, transcript::poseidon::poseidon_canonical_config};
    use std::borrow::Borrow;

    use crate::circuits::{
        deposit::Deposit, PlasmaFoldExternalInputs, PlasmaFoldExternalInputsVar,
    };

    use crate::circuits::PlasmaFoldCircuit;

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

    /// Get a deposit, `deposit_flag` specifies what the value for the deposit_flag field should be
    /// `deposit_valid` specifies whether the deposit proof should be valid or not
    pub fn get_deposit(
        config: &PoseidonConfig<Fr>,
        deposit_flag: bool,
        deposit_valid: bool,
    ) -> (MerkleTree<FieldMTConfig>, Deposit<FieldMTConfig, Fr>) {
        let mut leaves = [
            [Fr::from(123), Fr::from(456)],
            [Fr::from(789), Fr::from(101112)],
        ];
        let deposit_tree = MerkleTree::<FieldMTConfig>::new(&config, &config, leaves).unwrap();
        let deposit_proof = deposit_tree.generate_proof(0).unwrap();

        // we change leaves in the case where we want an invalid deposit
        if !deposit_valid {
            leaves[0] = [Fr::from(0), Fr::from(0)];
        }

        // initialize deposit
        let deposit = Deposit::<FieldMTConfig, Fr> {
            deposit_path: deposit_proof,
            deposit_root: deposit_tree.root(),
            deposit_value: leaves[0],
            deposit_flag,
        };

        (deposit_tree, deposit)
    }

    /// Initialize relevant constraint inputs for the plasma fold circuit. Returns the initialized
    /// variables and IVC state vector variable
    pub fn initialize_vars(
        cs: ConstraintSystemRef<Fr>,
        z_i: &[Fr],
        external_inputs: &PlasmaFoldExternalInputs<FieldMTConfig, Fr>,
    ) -> (
        Vec<FpVar<Fr>>,
        PlasmaFoldExternalInputsVar<FieldMTConfig, Fr, FieldMTConfigVar>,
    ) {
        let z_i = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(Vec::from(z_i))).unwrap();
        let external_inputs_var =
            PlasmaFoldExternalInputsVar::<FieldMTConfig, Fr, FieldMTConfigVar>::new_witness(
                cs.clone(),
                || Ok(external_inputs),
            )
            .unwrap();
        (z_i, external_inputs_var)
    }

    pub fn test_deposit_true_deposit_flag_true() -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let poseidon_config = poseidon_canonical_config::<Fr>();

        // initialize inputs
        let balance = Fr::zero();
        let (deposit_tree, deposit) = get_deposit(&poseidon_config, true, true);
        let external_inputs = PlasmaFoldExternalInputs { deposit, balance };
        let (z_i, external_inputs_var) =
            initialize_vars(cs.clone(), &[Fr::from(1)], &external_inputs);
        let i = 0;

        // initialize plasma fold circuit
        let field_mt_config = FieldMTConfig {
            poseidon_conf: poseidon_config,
        };
        let plasma_fold_circuit =
            PlasmaFoldCircuit::<FieldMTConfig, Fr, FieldMTConfigVar>::new(field_mt_config).unwrap();

        plasma_fold_circuit
            .generate_step_constraints(cs.clone(), i, z_i, external_inputs_var)
            .unwrap();

        let is_satisfied = cs.is_satisfied().unwrap();
        assert!(is_satisfied);
        is_satisfied
    }

    pub fn test_deposit_true_deposit_flag_false() -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let poseidon_config = poseidon_canonical_config::<Fr>();

        // initialize inputs
        let balance = Fr::zero();
        let (deposit_tree, deposit) = get_deposit(&poseidon_config, false, true);
        let external_inputs = PlasmaFoldExternalInputs { deposit, balance };
        let (z_i, external_inputs_var) =
            initialize_vars(cs.clone(), &[Fr::from(1)], &external_inputs);
        let i = 0;

        // initialize plasma fold circuit
        let field_mt_config = FieldMTConfig {
            poseidon_conf: poseidon_config,
        };
        let plasma_fold_circuit =
            PlasmaFoldCircuit::<FieldMTConfig, Fr, FieldMTConfigVar>::new(field_mt_config).unwrap();

        plasma_fold_circuit
            .generate_step_constraints(cs.clone(), i, z_i, external_inputs_var)
            .unwrap();

        let is_satisfied = cs.is_satisfied().unwrap();
        assert!(!is_satisfied);
        is_satisfied
    }

    pub fn test_deposit_false_deposit_flag_false() -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let poseidon_config = poseidon_canonical_config::<Fr>();

        // initialize inputs
        let balance = Fr::zero();
        let (deposit_tree, deposit) = get_deposit(&poseidon_config, false, false);
        let external_inputs = PlasmaFoldExternalInputs { deposit, balance };
        let (z_i, external_inputs_var) =
            initialize_vars(cs.clone(), &[Fr::from(1)], &external_inputs);
        let i = 0;

        // initialize plasma fold circuit
        let field_mt_config = FieldMTConfig {
            poseidon_conf: poseidon_config,
        };
        let plasma_fold_circuit =
            PlasmaFoldCircuit::<FieldMTConfig, Fr, FieldMTConfigVar>::new(field_mt_config).unwrap();

        plasma_fold_circuit
            .generate_step_constraints(cs.clone(), i, z_i, external_inputs_var)
            .unwrap();

        let is_satisfied = cs.is_satisfied().unwrap();
        assert!(is_satisfied);
        is_satisfied
    }
}
