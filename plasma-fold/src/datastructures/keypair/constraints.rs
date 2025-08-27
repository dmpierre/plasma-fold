use ark_crypto_primitives::{crh::poseidon::constraints::CRHParametersVar, sponge::Absorb};
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::alloc::AllocationMode;
use ark_r1cs_std::select::CondSelectGadget;
use ark_r1cs_std::{fields::fp::FpVar, groups::CurveVar, prelude::Boolean};
use ark_relations::gr1cs::Namespace;
use ark_relations::gr1cs::SynthesisError;
use std::borrow::Borrow;
use std::marker::PhantomData;

use crate::primitives::schnorr::SchnorrGadget;

use super::{PublicKey, Signature};

#[derive(Debug, Clone)]
pub struct PublicKeyVar<
    C: CurveGroup<BaseField: PrimeField + Absorb>,
    CVar: CurveVar<C, C::BaseField>,
> {
    pub key: CVar,
    pub _f: PhantomData<C>,
}

impl<C: CurveGroup<BaseField: Absorb + PrimeField>, CVar: CurveVar<C, C::BaseField>>
    AllocVar<PublicKey<C>, C::BaseField> for PublicKeyVar<C, CVar>
{
    fn new_variable<T: Borrow<PublicKey<C>>>(
        cs: impl Into<Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let f = f()?;
        let pk: &PublicKey<C> = f.borrow();
        let pk_var = CVar::new_variable(cs.clone(), || Ok(pk.key), mode)?;
        Ok(PublicKeyVar {
            key: pk_var,
            _f: PhantomData::<C>,
        })
    }
}

impl<C: CurveGroup<BaseField: Absorb + PrimeField>, CVar: CurveVar<C, C::BaseField>>
    CondSelectGadget<C::BaseField> for PublicKeyVar<C, CVar>
{
    fn conditionally_select(
        cond: &Boolean<C::BaseField>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        let key = cond.select(&true_value.key, &false_value.key)?;
        Ok(PublicKeyVar {
            key,
            _f: PhantomData::<C>,
        })
    }
}

#[derive(Clone, Debug)]
pub struct SignatureVar<F: PrimeField> {
    pub s: Vec<Boolean<F>>,
    pub e: Vec<Boolean<F>>,
}

impl<BF: PrimeField, SF: PrimeField> AllocVar<Signature<SF>, BF> for SignatureVar<BF> {
    fn new_variable<T: Borrow<Signature<SF>>>(
        cs: impl Into<Namespace<BF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let sig = f()?;
        let sig = sig.borrow();
        let s = sig.s.into_bigint().to_bits_le();
        let e = sig.e.into_bigint().to_bits_le();
        Ok(Self {
            s: Vec::new_variable(cs.clone(), || Ok(&s[..SF::MODULUS_BIT_SIZE as usize]), mode)?,
            e: Vec::new_variable(cs.clone(), || Ok(&e[..SF::MODULUS_BIT_SIZE as usize]), mode)?,
        })
    }
}

impl<C: CurveGroup<BaseField: Absorb + PrimeField>, CVar: CurveVar<C, C::BaseField>>
    PublicKeyVar<C, CVar>
{
    pub fn verify_signature<const W: usize>(
        &self,
        pp: &CRHParametersVar<C::BaseField>,
        m: &[FpVar<C::BaseField>],
        SignatureVar { s, e }: SignatureVar<C::BaseField>,
    ) -> Result<(), SynthesisError> {
        SchnorrGadget::verify::<W, C, CVar>(pp, &self.key, m, (s, e))
    }

    pub fn is_signature_valid<const W: usize>(
        &self,
        pp: &CRHParametersVar<C::BaseField>,
        m: &[FpVar<C::BaseField>],
        SignatureVar { s, e }: SignatureVar<C::BaseField>,
    ) -> Result<Boolean<C::BaseField>, SynthesisError> {
        SchnorrGadget::is_valid::<W, C, CVar>(pp, &self.key, m, (s, e))
    }
}
