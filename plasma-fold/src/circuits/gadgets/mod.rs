use ark_crypto_primitives::crh::CRHSchemeGadget;
use ark_crypto_primitives::crh::TwoToOneCRHSchemeGadget;
use ark_crypto_primitives::merkle_tree::constraints::ConfigGadget;
use ark_crypto_primitives::merkle_tree::constraints::PathVar;
use ark_crypto_primitives::merkle_tree::Path;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::Boolean;
use ark_relations::r1cs::SynthesisError;
use std::marker::PhantomData;

use ark_crypto_primitives::merkle_tree::Config;
use ark_ff::PrimeField;

pub struct TreeGadgets<P: Config, F: PrimeField, PG: ConfigGadget<P, F>> {
    _f: PhantomData<P>,
    _f1: PhantomData<F>,
    _f2: PhantomData<PG>,
}

pub struct TreeUpdateProof<P: Config<Leaf: Sized>> {
    pub prev_root: P::InnerDigest,
    pub prev_leaf: P::Leaf,
    pub path: Path<P>,
    pub new_root: P::InnerDigest,
    pub new_leaf: P::Leaf,
}

impl<P: Config<Leaf: Sized>> From<(P::InnerDigest, P::Leaf, Path<P>, P::InnerDigest, P::Leaf)>
    for TreeUpdateProof<P>
{
    fn from(value: (P::InnerDigest, P::Leaf, Path<P>, P::InnerDigest, P::Leaf)) -> Self {
        Self {
            prev_root: value.0,
            prev_leaf: value.1,
            path: value.2,
            new_root: value.3,
            new_leaf: value.4,
        }
    }
}

pub struct TreeUpdateProofVar<P: Config, F: PrimeField, PG: ConfigGadget<P, F, Leaf: Sized>> {
    pub prev_root: PG::InnerDigest,
    pub prev_leaf: PG::Leaf,
    pub path: PathVar<P, F, PG>,
    pub new_root: PG::InnerDigest,
    pub new_leaf: PG::Leaf,
}

impl<
        P: Config<Leaf: Sized + Clone>,
        F: PrimeField,
        PG: ConfigGadget<P, F, Leaf: AllocVar<P::Leaf, F>>,
    > AllocVar<TreeUpdateProof<P>, F> for TreeUpdateProofVar<P, F, PG>
{
    fn new_variable<T: std::borrow::Borrow<TreeUpdateProof<P>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let proof = f()?;
        let proof: &TreeUpdateProof<P> = proof.borrow();
        let cs = cs.into().cs();
        let prev_root =
            PG::InnerDigest::new_variable(cs.clone(), || Ok(proof.prev_root.clone()), mode)?;
        let new_root =
            PG::InnerDigest::new_variable(cs.clone(), || Ok(proof.new_root.clone()), mode)?;
        let prev_leaf = PG::Leaf::new_variable(cs.clone(), || Ok(proof.prev_leaf.clone()), mode)?;
        let new_leaf = PG::Leaf::new_variable(cs.clone(), || Ok(proof.new_leaf.clone()), mode)?;
        let path = PathVar::<P, F, PG>::new_variable(cs.clone(), || Ok(proof.path.clone()), mode)?;
        Ok(TreeUpdateProofVar {
            prev_root,
            prev_leaf,
            path,
            new_root,
            new_leaf,
        })
    }
}

impl<P: Config, F: PrimeField, PG: ConfigGadget<P, F>> TreeGadgets<P, F, PG> {
    pub fn compute_id_from_path_and_check(
        path: &PathVar<P, F, PG>,
        expected_id: &FpVar<F>,
    ) -> Result<(), SynthesisError> {
        let computed_id = Boolean::<F>::le_bits_to_fp(&path.get_leaf_position())?;
        computed_id.enforce_equal(expected_id)
    }

    pub fn update_and_check(
        leaf_params: &<<PG as ConfigGadget<P, F>>::LeafHash as CRHSchemeGadget<
            <P as Config>::LeafHash,
            F,
        >>::ParametersVar,
        two_to_one_params: &<<PG as ConfigGadget<P, F>>::TwoToOneHash as TwoToOneCRHSchemeGadget<
            <P as Config>::TwoToOneHash,
            F,
        >>::ParametersVar,
        update_proof: TreeUpdateProofVar<P, F, PG>,
    ) -> Result<Boolean<F>, SynthesisError>
    where
        <PG as ConfigGadget<P, F>>::Leaf: Sized,
    {
        update_proof.path.update_and_check(
            leaf_params,
            two_to_one_params,
            &update_proof.prev_root,
            &update_proof.new_root,
            &update_proof.prev_leaf,
            &update_proof.new_leaf,
        )
    }
}
