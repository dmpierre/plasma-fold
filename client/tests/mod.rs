#[cfg(test)]
pub mod tests {
    use ark_bn254::Fr;
    use ark_ff::PrimeField;
    use ark_grumpkin::constraints::GVar;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
    use ark_serialize::{CanonicalSerialize, Compress};
    use ark_std::rand::thread_rng;
    use client::{ClientCircuitPoseidon, ClientCircuitSha};
    use folding_schemes::arith::Arith;
    use folding_schemes::folding::nova::{ProverParams, VerifierParams};
    use folding_schemes::{
        commitment::pedersen::Pedersen, frontend::FCircuit,
        transcript::poseidon::poseidon_canonical_config,
    };
    use folding_schemes::{Error, Field, FoldingScheme};
    use std::marker::PhantomData;

    #[derive(Clone, Copy, Debug)]
    pub struct CubicFCircuit<F: PrimeField> {
        _f: PhantomData<F>,
    }

    impl<F: Field> FCircuit<F> for CubicFCircuit<F> {
        type Params = ();
        type ExternalInputs = ();
        type ExternalInputsVar = ();

        fn new(_params: Self::Params) -> Result<Self, Error> {
            Ok(Self { _f: PhantomData })
        }
        fn state_len(&self) -> usize {
            1
        }
        fn generate_step_constraints(
            &self,
            cs: ConstraintSystemRef<F>,
            _i: usize,
            z_i: Vec<FpVar<F>>,
            _external_inputs: Self::ExternalInputsVar,
        ) -> Result<Vec<FpVar<F>>, SynthesisError> {
            let five = FpVar::<F>::new_constant(cs.clone(), F::from(5u32))?;
            let z_i = z_i[0].clone();

            Ok(vec![&z_i * &z_i * &z_i + &z_i + &five])
        }
    }
    use ark_bn254::G1Projective as Projective;
    use ark_grumpkin::Projective as Projective2;

    use folding_schemes::folding::nova::*;

    #[test]
    pub fn test_print_serialized_params() {
        pub const TEST_BATCH_SIZE: usize = 10;
        let pp = poseidon_canonical_config();
        let mut rng = thread_rng();

        let f_circuit =
            ClientCircuitPoseidon::<Fr, Projective2, GVar, TEST_BATCH_SIZE>::new(pp.clone())
                .unwrap();

        let nova_preprocess_params = PreprocessorParam::new(pp.clone(), f_circuit.clone());
        let (pp, vp): (
            ProverParams<Projective, Projective2, Pedersen<Projective>, Pedersen<Projective2>>,
            VerifierParams<Projective, Projective2, Pedersen<Projective>, Pedersen<Projective2>>,
        ) = Nova::<
            Projective,
            Projective2,
            ClientCircuitPoseidon<Fr, Projective2, GVar, TEST_BATCH_SIZE>,
            Pedersen<Projective>,
            Pedersen<Projective2>,
            false,
        >::preprocess(&mut rng, &nova_preprocess_params)
        .unwrap();

        let pp_size =
            pp.serialized_size(Compress::Yes) + pp.poseidon_config.serialized_size(Compress::Yes);

        let vp_size = vp.serialized_size(Compress::Yes)
            + vp.r1cs.serialized_size(Compress::Yes)
            + vp.cf_r1cs.serialized_size(Compress::Yes);

        println!(
            "Batch size: {}, total circuit size: {}, params size: {}",
            TEST_BATCH_SIZE,
            vp.r1cs.n_constraints(),
            pp_size + vp_size
        );
    }

    #[test]
    pub fn test_print_serialized_params_sha() {
        pub const TEST_BATCH_SIZE: usize = 2;
        let pp = poseidon_canonical_config();
        let mut rng = thread_rng();

        let f_circuit =
            ClientCircuitSha::<Fr, Projective2, GVar, TEST_BATCH_SIZE>::new(pp.clone()).unwrap();

        let nova_preprocess_params = PreprocessorParam::new(pp.clone(), f_circuit.clone());
        let (pp, vp): (
            ProverParams<Projective, Projective2, Pedersen<Projective>, Pedersen<Projective2>>,
            VerifierParams<Projective, Projective2, Pedersen<Projective>, Pedersen<Projective2>>,
        ) = Nova::<
            Projective,
            Projective2,
            ClientCircuitSha<Fr, Projective2, GVar, TEST_BATCH_SIZE>,
            Pedersen<Projective>,
            Pedersen<Projective2>,
            false,
        >::preprocess(&mut rng, &nova_preprocess_params)
        .unwrap();

        let pp_size =
            pp.serialized_size(Compress::Yes) + pp.poseidon_config.serialized_size(Compress::Yes);

        let vp_size = vp.serialized_size(Compress::Yes)
            + vp.r1cs.serialized_size(Compress::Yes)
            + vp.cf_r1cs.serialized_size(Compress::Yes);

        println!(
            "[SHA] Batch size: {}, total circuit size: {}, params size: {}",
            TEST_BATCH_SIZE,
            vp.r1cs.n_constraints(),
            pp_size + vp_size
        );
    }
}
