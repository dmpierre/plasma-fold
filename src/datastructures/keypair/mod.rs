use crate::primitives::schnorr::BigUintVar;
use crate::primitives::schnorr::BitsVar;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::alloc::AllocationMode;
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::eq::EqGadget;
use ark_relations::r1cs::Namespace;
use std::borrow::Borrow;
use std::marker::PhantomData;

use ark_crypto_primitives::{
    crh::{
        poseidon::{
            constraints::{CRHGadget, CRHParametersVar},
            CRH,
        },
        CRHScheme, CRHSchemeGadget,
    },
    sponge::{poseidon::PoseidonConfig, Absorb},
    Error,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{fields::fp::FpVar, groups::CurveVar, prelude::Boolean};
use ark_relations::r1cs::SynthesisError;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;

use crate::primitives::schnorr::Schnorr;

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
        loop {
            let k = C::ScalarField::rand(rng);
            let (x, y) = C::generator().mul(k).into_affine().xy().unwrap();

            let h = CRH::evaluate(pp, [x, y, m])?;
            let mut h_bits = h.into_bigint().to_bits_le();
            h_bits.truncate(C::ScalarField::MODULUS_BIT_SIZE as usize + 1);
            let h = <C::ScalarField as PrimeField>::BigInt::from_bits_le(&h_bits);

            if let Some(e) = C::ScalarField::from_bigint(h) {
                return Ok(Signature {
                    s: k - self.key * e,
                    e,
                });
            };
        }
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
        let (x, y) = (C::generator().mul(s) + self.key.mul(e))
            .into_affine()
            .xy()
            .unwrap();

        let h = CRH::evaluate(pp, [x, y, message])?;
        let mut h_bits = h.into_bigint().to_bits_le();
        h_bits.truncate(C::ScalarField::MODULUS_BIT_SIZE as usize);
        let h = <C::ScalarField as PrimeField>::BigInt::from_bits_le(&h_bits);

        Ok(C::ScalarField::from_bigint(h) == Some(*e))
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
        let len = C::ScalarField::MODULUS_BIT_SIZE as usize;

        let g = CVar::constant(C::generator());
        let r = g.scalar_mul_le(s.iter())? + self.key.scalar_mul_le(e.iter())?;

        let mut xy = r.to_constraint_field()?;
        xy.pop();
        xy.push(m);

        let h = CRHGadget::evaluate(pp, &xy)?;
        let mut h_bits = h.to_bits_le()?;
        h_bits.truncate(len);

        BigUintVar::<C::BaseField, W>(h_bits.chunks(W).map(BitsVar::from).collect())
            .enforce_lt(&BigUintVar::constant(C::ScalarField::MODULUS.into(), len)?)?;

        Boolean::le_bits_to_fp(&h_bits[..len - 1])?
            .enforce_equal(&Boolean::le_bits_to_fp(&e[..len - 1])?)?;
        h_bits[len - 1].enforce_equal(&e[len - 1])?;

        Ok(())
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
