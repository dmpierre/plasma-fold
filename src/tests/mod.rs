mod utils;

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
    use ark_ff::{AdditiveGroup, Zero};
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_relations::r1cs::ConstraintSystem;
    use folding_schemes::{frontend::FCircuit, transcript::poseidon::poseidon_canonical_config};
    use std::borrow::Borrow;

    use crate::tests::utils::{get_deposit, init};

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

    pub fn test_deposit_true_deposit_flag_true() -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let poseidon_config = poseidon_canonical_config::<Fr>();

        // initialize inputs, with correct deposit and deposit flag at true
        let (deposit_tree, deposit) = get_deposit(&poseidon_config, &poseidon_config, true, true);
        let (external_inputs, z_i_vars, external_inputs_vars) = init(
            cs.clone(),
            &[Fr::from(1), Fr::from(1)],
            Some(Fr::ZERO),
            None,
            Some(deposit),
        );
        let i = 0;

        // initialize plasma fold circuit
        let field_mt_config = FieldMTConfig {
            poseidon_conf: poseidon_config,
        };
        let plasma_fold_circuit =
            PlasmaFoldCircuit::<FieldMTConfig, Fr, FieldMTConfigVar>::new(field_mt_config).unwrap();

        plasma_fold_circuit
            .generate_step_constraints(cs.clone(), i, z_i_vars, external_inputs_vars)
            .unwrap();

        let is_satisfied = cs.is_satisfied().unwrap();
        assert!(is_satisfied);
        is_satisfied
    }

    pub fn test_deposit_true_deposit_flag_false() -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let poseidon_config = poseidon_canonical_config::<Fr>();

        // initialize inputs
        let (deposit_tree, deposit) = get_deposit(&poseidon_config, &poseidon_config, false, true);
        let (external_inputs, z_i_vars, external_inputs_vars) = init(
            cs.clone(),
            &[Fr::from(1), Fr::from(1)],
            Some(Fr::ZERO),
            None,
            Some(deposit),
        );
        let i = 0;

        // initialize plasma fold circuit
        let field_mt_config = FieldMTConfig {
            poseidon_conf: poseidon_config,
        };
        let plasma_fold_circuit =
            PlasmaFoldCircuit::<FieldMTConfig, Fr, FieldMTConfigVar>::new(field_mt_config).unwrap();
        plasma_fold_circuit
            .generate_step_constraints(cs.clone(), i, z_i_vars, external_inputs_vars)
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
        let (deposit_tree, deposit) = get_deposit(&poseidon_config, &poseidon_config, false, false);
        let (external_inputs, z_i_vars, external_inputs_vars) = init(
            cs.clone(),
            &[Fr::from(1), Fr::from(1)],
            Some(Fr::ZERO),
            None,
            Some(deposit),
        );
        let i = 0;

        // initialize plasma fold circuit
        let field_mt_config = FieldMTConfig {
            poseidon_conf: poseidon_config,
        };
        let plasma_fold_circuit =
            PlasmaFoldCircuit::<FieldMTConfig, Fr, FieldMTConfigVar>::new(field_mt_config).unwrap();

        plasma_fold_circuit
            .generate_step_constraints(cs.clone(), i, z_i_vars, external_inputs_vars)
            .unwrap();

        let is_satisfied = cs.is_satisfied().unwrap();
        assert!(is_satisfied);
        is_satisfied
    }
}
