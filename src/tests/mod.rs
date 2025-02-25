pub mod tests {
    use ark_bn254::fr::Fr;
    use ark_crypto_primitives::{
        crh::poseidon::{
            constraints::{CRHGadget, TwoToOneCRHGadget},
            TwoToOneCRH, CRH,
        },
        merkle_tree::{constraints::ConfigGadget, Config, IdentityDigestConverter, MerkleTree},
        sponge::poseidon::PoseidonConfig,
    };
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
    use ark_relations::r1cs::ConstraintSystem;
    use folding_schemes::{frontend::FCircuit, transcript::poseidon::poseidon_canonical_config};
    use std::borrow::Borrow;

    use crate::circuits::{
        Deposit, PlasmaFoldCircuit, PlasmaFoldExternalInputs, PlasmaFoldExternalInputsVar,
    };

    impl Borrow<PoseidonConfig<Fr>> for FieldMTConfig {
        fn borrow(&self) -> &PoseidonConfig<Fr> {
            return self.poseidon_conf.borrow();
        }
    }

    #[derive(Debug, Clone)]
    struct FieldMTConfig {
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
    struct FieldMTConfigVar;
    impl ConfigGadget<FieldMTConfig, Fr> for FieldMTConfigVar {
        type Leaf = [FpVar<Fr>];
        type LeafDigest = FpVar<Fr>;
        type LeafInnerConverter = IdentityDigestConverter<FpVar<Fr>>;
        type InnerDigest = FpVar<Fr>;
        type LeafHash = CRHGadget<Fr>;
        type TwoToOneHash = TwoToOneCRHGadget<Fr>;
    }

    pub fn test_deposit() -> bool {
        let leaf_crh_params = poseidon_canonical_config::<Fr>();
        let two_to_one_params = leaf_crh_params.clone();
        let leaves = [
            [Fr::from(123), Fr::from(456)],
            [Fr::from(789), Fr::from(101112)],
        ];
        let deposit_tree =
            MerkleTree::<FieldMTConfig>::new(&leaf_crh_params, &two_to_one_params, leaves).unwrap();
        let deposit_proof = deposit_tree.generate_proof(0).unwrap();

        // initialize deposit
        let deposit = Deposit::<FieldMTConfig, Fr> {
            deposit_path: deposit_proof,
            deposit_root: deposit_tree.root(),
            deposit_value: leaves[0],
        };
        let external_inputs = PlasmaFoldExternalInputs { deposit };

        let cs = ConstraintSystem::<Fr>::new_ref();

        let i = 0;
        let z_i =
            Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(Vec::from([Fr::from(1)]))).unwrap();
        let external_inputs_var =
            PlasmaFoldExternalInputsVar::<FieldMTConfig, Fr, FieldMTConfigVar>::new_witness(
                cs.clone(),
                || Ok(external_inputs),
            )
            .unwrap();
        let field_mt_config = FieldMTConfig {
            poseidon_conf: poseidon_canonical_config(),
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
