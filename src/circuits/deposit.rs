use ark_crypto_primitives::merkle_tree::{
    constraints::{ConfigGadget, PathVar},
    Config, Path,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, prelude::Boolean};

#[derive(Debug, Clone)]
pub struct Deposit<P: Config, F: PrimeField> {
    pub path: Path<P>,        // path from leaf to root of the deposit tree
    pub root: P::InnerDigest, // root of the deposit tree
    pub value: [F; 2],        // (token_index, value)
    pub flag: bool,           // indicates whether a deposit occured
}

#[derive(Debug, Clone)]
pub struct DepositVar<P: Config, F: PrimeField, PG: ConfigGadget<P, F>> {
    pub path: PathVar<P, F, PG>,
    pub root: PG::InnerDigest,
    pub value: [FpVar<F>; 2], // (token_index, value)
    pub flag: Boolean<F>,
}

impl<P: Config, F: PrimeField> Default for Deposit<P, F> {
    fn default() -> Self {
        let default_deposit_path = Path::default();
        let default_deposit_root = P::InnerDigest::default();
        let default_deposit_value = [F::ZERO, F::ZERO];
        let default_deposit_flag = bool::default(); // false
        return Deposit {
            path: default_deposit_path,
            root: default_deposit_root,
            value: default_deposit_value,
            flag: default_deposit_flag,
        };
    }
}

impl<P: Config, F: PrimeField, PG: ConfigGadget<P, F>> AllocVar<Deposit<P, F>, F>
    for DepositVar<P, F, PG>
{
    fn new_variable<T: std::borrow::Borrow<Deposit<P, F>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        f().and_then(|val| {
            let deposit: &Deposit<P, F> = val.borrow();
            let root =
                PG::InnerDigest::new_witness(ark_relations::ns!(cs, "deposit_root"), || {
                    Ok(&deposit.root)
                })?;
            let path =
                PathVar::<P, F, PG>::new_witness(ark_relations::ns!(cs, "deposit_path"), || {
                    Ok(&deposit.path)
                })?;
            let value = AllocVar::<[F; 2], F>::new_witness(
                ark_relations::ns!(cs, "deposit_value"),
                || Ok(&deposit.value),
            )?;
            let flag =
                Boolean::new_witness(ark_relations::ns!(cs, "deposit_flag"), || Ok(deposit.flag))?;
            Ok(DepositVar {
                path,
                root,
                value,
                flag,
            })
        })
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
    use ark_ff::Field;
    use ark_r1cs_std::{fields::fp::FpVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;
    use folding_schemes::{frontend::FCircuit, transcript::poseidon::poseidon_canonical_config};
    use std::borrow::Borrow;

    use crate::tests::utils::{get_deposit, init_external_inputs, init_vars};

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
        let (salt, balance) = (Fr::ONE, Fr::ONE);
        let (prev_block_hash, nonce) = (Fr::ONE, Fr::ONE);
        let external_inputs = init_external_inputs(salt, balance, None, Some(deposit));
        let z_i = [
            prev_block_hash,
            nonce,
            external_inputs
                .compute_public_state(&poseidon_config)
                .unwrap(),
        ];
        let (z_i_vars, external_inputs_vars) = init_vars(cs.clone(), &z_i, &external_inputs);

        // initialize plasma fold circuit
        let field_mt_config = FieldMTConfig {
            poseidon_conf: poseidon_config,
        };
        let plasma_fold_circuit =
            PlasmaFoldCircuit::<FieldMTConfig, Fr, FieldMTConfigVar>::new(field_mt_config).unwrap();

        plasma_fold_circuit
            .generate_step_constraints(cs.clone(), 0, z_i_vars, external_inputs_vars)
            .unwrap();

        let is_satisfied = cs.is_satisfied().unwrap();
        assert!(is_satisfied);
        is_satisfied
    }

    pub fn test_deposit_true_deposit_flag_false() -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let poseidon_config = poseidon_canonical_config::<Fr>();

        // initialize inputs, with correct deposit and deposit flag at true
        let (deposit_tree, deposit) = get_deposit(&poseidon_config, &poseidon_config, false, true);
        let (salt, balance) = (Fr::ONE, Fr::ONE);
        let (prev_block_hash, nonce) = (Fr::ONE, Fr::ONE);
        let external_inputs = init_external_inputs(salt, balance, None, Some(deposit));
        let z_i = [
            prev_block_hash,
            nonce,
            external_inputs
                .compute_public_state(&poseidon_config)
                .unwrap(),
        ];
        let (z_i_vars, external_inputs_vars) = init_vars(cs.clone(), &z_i, &external_inputs);

        // initialize plasma fold circuit
        let field_mt_config = FieldMTConfig {
            poseidon_conf: poseidon_config,
        };
        let plasma_fold_circuit =
            PlasmaFoldCircuit::<FieldMTConfig, Fr, FieldMTConfigVar>::new(field_mt_config).unwrap();

        plasma_fold_circuit
            .generate_step_constraints(cs.clone(), 0, z_i_vars, external_inputs_vars)
            .unwrap();

        let is_satisfied = cs.is_satisfied().unwrap();
        assert!(!is_satisfied);
        !is_satisfied
    }

    pub fn test_deposit_false_deposit_flag_false() -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let poseidon_config = poseidon_canonical_config::<Fr>();

        // initialize inputs, with correct deposit and deposit flag at true
        let (deposit_tree, deposit) = get_deposit(&poseidon_config, &poseidon_config, false, false);
        let (salt, balance) = (Fr::ONE, Fr::ONE);
        let (prev_block_hash, nonce) = (Fr::ONE, Fr::ONE);
        let external_inputs = init_external_inputs(salt, balance, None, Some(deposit));
        let z_i = [
            prev_block_hash,
            nonce,
            external_inputs
                .compute_public_state(&poseidon_config)
                .unwrap(),
        ];
        let (z_i_vars, external_inputs_vars) = init_vars(cs.clone(), &z_i, &external_inputs);

        // initialize plasma fold circuit
        let field_mt_config = FieldMTConfig {
            poseidon_conf: poseidon_config,
        };
        let plasma_fold_circuit =
            PlasmaFoldCircuit::<FieldMTConfig, Fr, FieldMTConfigVar>::new(field_mt_config).unwrap();
        plasma_fold_circuit
            .generate_step_constraints(cs.clone(), 0, z_i_vars, external_inputs_vars)
            .unwrap();
        let is_satisfied = cs.is_satisfied().unwrap();
        assert!(is_satisfied);
        is_satisfied
    }

    pub fn test_balance_is_not_updated_when_flag_is_false() -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let poseidon_config = poseidon_canonical_config::<Fr>();

        // initialize inputs, with correct deposit and deposit flag at true
        let (deposit_tree, deposit) = get_deposit(&poseidon_config, &poseidon_config, false, false);
        let (salt, balance) = (Fr::ONE, Fr::ONE);
        let (prev_block_hash, nonce) = (Fr::ONE, Fr::ONE);
        let external_inputs = init_external_inputs(salt, balance, None, Some(deposit));
        let z_i = [
            prev_block_hash,
            nonce,
            external_inputs
                .compute_public_state(&poseidon_config)
                .unwrap(),
        ];
        let (z_i_vars, external_inputs_vars) = init_vars(cs.clone(), &z_i, &external_inputs);

        // initialize plasma fold circuit
        let field_mt_config = FieldMTConfig {
            poseidon_conf: poseidon_config,
        };
        let plasma_fold_circuit =
            PlasmaFoldCircuit::<FieldMTConfig, Fr, FieldMTConfigVar>::new(field_mt_config).unwrap();
        let new_z_i = plasma_fold_circuit
            .generate_step_constraints(cs.clone(), 0, z_i_vars, external_inputs_vars)
            .unwrap();
        let is_satisfied = cs.is_satisfied().unwrap();
        assert!(is_satisfied);
        assert_eq!(new_z_i[2].value().unwrap(), z_i[2]);
        new_z_i[2].value().unwrap() == z_i[2]
    }
}
