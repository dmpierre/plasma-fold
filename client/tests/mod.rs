#[cfg(test)]
pub mod tests {
    use ark_bn254::Fr;
    use ark_ff::PrimeField;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
    use ark_serialize::CanonicalSerialize;
    use ark_std::rand::thread_rng;
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
    use folding_schemes::Curve;

    pub fn output_serialized_params() {
        pub const TEST_BATCH_SIZE: usize = 2;
        let pp = poseidon_canonical_config();
        let mut rng = thread_rng();

        let f_circuit = CubicFCircuit::new(()).unwrap();
        let nova_preprocess_params = PreprocessorParam::new(pp.clone(), f_circuit.clone());
        let (pp, vp): (
            ProverParams<Projective, Projective2, Pedersen<Projective>, Pedersen<Projective2>>,
            VerifierParams<Projective, Projective2, Pedersen<Projective>, Pedersen<Projective2>>,
        ) = Nova::<
            Projective,
            Projective2,
            CubicFCircuit<Fr>,
            Pedersen<Projective>,
            Pedersen<Projective2>,
            false,
        >::preprocess(&mut rng, &nova_preprocess_params)
        .unwrap();

        let mut writer = vec![];
        let pp_size = pp.serialize_compressed(&mut writer).unwrap();
    }
}
