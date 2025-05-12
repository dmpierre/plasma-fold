use ark_crypto_primitives::{
    crh::poseidon::constraints::CRHParametersVar,
    sponge::{poseidon::PoseidonConfig, Absorb},
    Error,
};
use ark_ec::{short_weierstrass::SWCurveConfig, CurveConfig, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{alloc::AllocVar, groups::curves::short_weierstrass::ProjectiveVar};
use ark_r1cs_std::{alloc::AllocationMode, fields::FieldVar};
use ark_r1cs_std::{fields::fp::FpVar, groups::CurveVar, prelude::Boolean};
use ark_relations::r1cs::Namespace;
use ark_relations::r1cs::SynthesisError;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;
use std::borrow::Borrow;
use std::marker::PhantomData;

use crate::primitives::schnorr::Schnorr;
use crate::primitives::schnorr::SchnorrGadget;

// Schnorr secret key
#[derive(Debug, CanonicalSerialize)]
pub struct SecretKey<F: PrimeField> {
    pub key: F,
}

impl<F: PrimeField> SecretKey<F> {
    pub fn sign<C: CurveGroup<ScalarField = F, BaseField: PrimeField + Absorb>>(
        &self,
        pp: &PoseidonConfig<C::BaseField>,
        m: C::BaseField,
        rng: &mut impl Rng,
    ) -> Result<Signature<C::ScalarField>, Error> {
        let (s, e) = Schnorr::sign::<C>(pp, self.key, m, rng)?;
        Ok(Signature { s, e })
    }
}

// Schnorr public key
#[derive(Debug, CanonicalSerialize)]
pub struct PublicKey<C: CurveGroup> {
    pub key: C,
}

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

// Schnorr Signature, which is tuple (s, e)
pub struct Signature<F: PrimeField> {
    pub s: F,
    pub e: F,
}

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

impl<C: CurveGroup<BaseField: PrimeField + Absorb>> PublicKey<C> {
    pub fn verify_signature(
        &self,
        pp: &PoseidonConfig<C::BaseField>,
        message: C::BaseField,
        Signature { s, e }: &Signature<C::ScalarField>,
    ) -> Result<bool, Error> {
        Schnorr::verify::<C>(pp, &self.key, message, (*s, *e))
    }
}

impl<C: CurveGroup<BaseField: Absorb + PrimeField>, CVar: CurveVar<C, C::BaseField>>
    PublicKeyVar<C, CVar>
{
    pub fn verify_signature<const W: usize>(
        &self,
        pp: &CRHParametersVar<C::BaseField>,
        m: FpVar<C::BaseField>,
        SignatureVar { s, e }: SignatureVar<C::BaseField>,
    ) -> Result<(), SynthesisError> {
        SchnorrGadget::verify::<W, C, CVar>(pp, &self.key, m, (s, e))
    }
}

#[derive(Debug)]
pub struct KeyPair<C: CurveGroup> {
    pub sk: SecretKey<C::ScalarField>,
    pub pk: PublicKey<C>,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>> KeyPair<C> {
    pub fn new(rng: &mut impl Rng) -> Self {
        let (sk, pk) = Schnorr::key_gen::<C>(rng);
        Self {
            sk: SecretKey { key: sk },
            pk: PublicKey { key: pk },
        }
    }
}
