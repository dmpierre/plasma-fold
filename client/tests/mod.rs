#[cfg(test)]
pub mod tests {
    use ark_bn254::Fr;
    use ark_grumpkin::constraints::GVar;
    use ark_serialize::{CanonicalSerialize, Compress};
    use ark_std::rand::thread_rng;
    use client::{ClientCircuitPoseidon, ClientCircuitSha};
    use folding_schemes::arith::Arith;
    use folding_schemes::folding::nova::{ProverParams, VerifierParams};
    use folding_schemes::FoldingScheme;
    use folding_schemes::{
        commitment::pedersen::Pedersen, frontend::FCircuit,
        transcript::poseidon::poseidon_canonical_config,
    };

    use ark_bn254::G1Projective as Projective;
    use ark_grumpkin::Projective as Projective2;

    use folding_schemes::folding::nova::*;

    #[test]
    pub fn test_print_serialized_params() {
        pub const TEST_BATCH_SIZE: usize = 5;
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
            "Batch size: {}, total circuit size: {}, params size: {} {} {} {}",
            TEST_BATCH_SIZE,
            vp.r1cs.n_constraints(),
            pp_size,
            vp.serialized_size(Compress::Yes),
            vp.r1cs.serialized_size(Compress::Yes),
            vp.cf_r1cs.serialized_size(Compress::Yes)
        );
    }

    #[test]
    pub fn test_print_serialized_params_sha() {
        pub const TEST_BATCH_SIZE: usize = 1;
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

        println!(
            "Batch size: {}, total circuit size: {}, params size: {} {} {} {}",
            TEST_BATCH_SIZE,
            vp.r1cs.n_constraints(),
            pp_size,
            vp.serialized_size(Compress::Yes),
            vp.r1cs.serialized_size(Compress::Yes),
            vp.cf_r1cs.serialized_size(Compress::Yes)
        );
    }
}
