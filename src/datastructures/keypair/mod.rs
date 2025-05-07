use crate::primitives::schnorr::BigUintVar;
use crate::primitives::schnorr::BitsVar;
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::eq::EqGadget;
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
use ark_std::{rand::Rng, UniformRand};

use crate::primitives::schnorr::Schnorr;

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
pub type Signature<C: CurveGroup> = (C::ScalarField, C::ScalarField);
pub type SignatureVar<C: CurveGroup> = (Vec<Boolean<C::BaseField>>, Vec<Boolean<C::BaseField>>);

impl<C: CurveGroup<BaseField: PrimeField + Absorb>> PublicKey<C> {
    pub fn verify_signature(
        &self,
        pp: &PoseidonConfig<C::BaseField>,
        message: C::BaseField,
        sig: Signature<C>,
    ) -> Result<bool, Error> {
        let (x, y) = (C::generator().mul(sig.0) + self.key.mul(sig.1))
            .into_affine()
            .xy()
            .unwrap();

        let h = CRH::evaluate(pp, [x, y, message])?;
        let mut h_bits = h.into_bigint().to_bits_le();
        h_bits.truncate(C::ScalarField::MODULUS_BIT_SIZE as usize);
        let h = <C::ScalarField as PrimeField>::BigInt::from_bits_le(&h_bits);

        Ok(C::ScalarField::from_bigint(h) == Some(sig.1))
    }
}

impl<C: CurveGroup<BaseField: Absorb + PrimeField>, CVar: CurveVar<C, C::BaseField>>
    PublicKeyVar<C, CVar>
{
    pub fn verify_signature<const W: usize>(
        &self,
        pp: &CRHParametersVar<C::BaseField>,
        m: FpVar<C::BaseField>,
        sig: SignatureVar<C>,
    ) -> Result<(), SynthesisError> {
        let len_le_rep_modulus = C::ScalarField::MODULUS.to_bits_le().len();
        let len = C::ScalarField::MODULUS_BIT_SIZE as usize;

        assert_eq!(sig.1.len(), len_le_rep_modulus);
        assert_eq!(sig.0.len(), len_le_rep_modulus);

        let g = CVar::constant(C::generator());
        let r = g.scalar_mul_le(sig.0.iter())? + self.key.scalar_mul_le(sig.1.iter())?;

        let mut xy = r.to_constraint_field()?;
        xy.pop();
        xy.push(m);

        let h = CRHGadget::evaluate(pp, &xy)?;
        let mut h_bits = h.to_bits_le()?;
        h_bits.truncate(len);

        BigUintVar::<C::BaseField, W>(h_bits.chunks(W).map(BitsVar::from).collect())
            .enforce_lt(&BigUintVar::constant(C::ScalarField::MODULUS.into(), len)?)?;

        Boolean::le_bits_to_fp(&h_bits[..len - 1])?
            .enforce_equal(&Boolean::le_bits_to_fp(&sig.1[..len - 1])?)?;
        h_bits[len - 1].enforce_equal(&sig.1[len - 1])?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct KeyPair<C: CurveGroup> {
    pub sk: C::ScalarField,
    pub pk: PublicKey<C>,
}
impl<C: CurveGroup<BaseField: PrimeField + Absorb>> KeyPair<C> {
    pub fn new(rng: &mut impl Rng) -> Self {
        let (sk, pubk) = Schnorr::key_gen::<C>(rng);
        let pk = PublicKey { key: pubk };
        Self { sk, pk }
    }

    pub fn sign(
        &self,
        pp: &PoseidonConfig<C::BaseField>,
        m: C::BaseField,
        rng: &mut impl Rng,
    ) -> Result<Signature<C>, Error> {
        loop {
            let k = C::ScalarField::rand(rng);
            let (x, y) = C::generator().mul(k).into_affine().xy().unwrap();

            let h = CRH::evaluate(pp, [x, y, m])?;
            let mut h_bits = h.into_bigint().to_bits_le();
            h_bits.truncate(C::ScalarField::MODULUS_BIT_SIZE as usize + 1);
            let h = <C::ScalarField as PrimeField>::BigInt::from_bits_le(&h_bits);

            if let Some(e) = C::ScalarField::from_bigint(h) {
                return Ok((k - self.sk * e, e));
            };
        }
    }
}
