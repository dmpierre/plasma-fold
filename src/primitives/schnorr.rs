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
use ark_ec::{ AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    convert::ToBitsGadget,
    fields::fp::FpVar,
    prelude::{Boolean, CurveVar, EqGadget, FieldVar},
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_std::{borrow::Borrow, cmp::max, rand::Rng, UniformRand};
use num::{BigUint, One, Zero};

pub struct Schnorr {}

impl Schnorr {
    pub fn key_gen<C: CurveGroup>(rng: &mut impl Rng) -> (C::ScalarField, C) {
        let sk = C::ScalarField::rand(rng);
        let pk = C::generator().mul(sk);

        (sk, pk)
    }

    pub fn sign<C: CurveGroup<BaseField: PrimeField + Absorb>>(
        pp: &PoseidonConfig<C::BaseField>,
        sk: C::ScalarField,
        m: C::BaseField,
        rng: &mut impl Rng,
    ) -> Result<(C::ScalarField, C::ScalarField), Error>
    {
        loop {
            let k = C::ScalarField::rand(rng);
            let (x, y) = C::generator().mul(k).into_affine().xy().unwrap();

            let h = CRH::evaluate(pp, [x, y, m])?;
            let mut h_bits = h.into_bigint().to_bits_le();
            h_bits.truncate(C::ScalarField::MODULUS_BIT_SIZE as usize + 1);
            let h = <C::ScalarField as PrimeField>::BigInt::from_bits_le(&h_bits);

            if let Some(e) = C::ScalarField::from_bigint(h) {
                return Ok((k - sk * e, e));
            };
        }
    }

    pub fn verify<C: CurveGroup<BaseField: PrimeField + Absorb>>(
        pp: &PoseidonConfig<C::BaseField>,
        pk: &C,
        message: C::BaseField,
        (s, e): (C::ScalarField, C::ScalarField),
    ) -> Result<bool, Error>
    {
        let (x, y) = (C::generator().mul(s) + pk.mul(e))
            .into_affine()
            .xy()
            .unwrap();

        let h = CRH::evaluate(pp, [x, y, message])?;
        let mut h_bits = h.into_bigint().to_bits_le();
        h_bits.truncate(C::ScalarField::MODULUS_BIT_SIZE as usize);
        let h = <C::ScalarField as PrimeField>::BigInt::from_bits_le(&h_bits);

        Ok(C::ScalarField::from_bigint(h) == Some(e))
    }
}

#[derive(Clone)]
pub struct BitsVar<F: PrimeField, const W: usize>(pub FpVar<F>, pub BigUint);

impl<F: PrimeField, const W: usize> From<&[Boolean<F>]> for BitsVar<F, W> {
    fn from(bits: &[Boolean<F>]) -> Self {
        Self(
            Boolean::le_bits_to_fp(bits).unwrap(),
            (BigUint::one() << bits.len()) - BigUint::one(),
        )
    }
}

impl<F: PrimeField, const W: usize> R1CSVar<F> for BitsVar<F, W> {
    type Value = F;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.0.cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        self.0.value()
    }
}
#[derive(Clone)]
pub struct BigUintVar<F: PrimeField, const W: usize>(pub Vec<BitsVar<F, W>>);

impl<F: PrimeField, const W: usize> AllocVar<(BigUint, usize), F> for BigUintVar<F, W> {
    fn new_variable<T: Borrow<(BigUint, usize)>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        let v = f()?;
        let (x, l) = v.borrow();

        let mut limbs = vec![];
        for chunk in (0..*l)
            .map(|i| x.bit(i as u64))
            .collect::<Vec<_>>()
            .chunks(W)
        {
            let limb = F::from_bigint(F::BigInt::from_bits_le(chunk)).unwrap();
            let limb = FpVar::new_variable(cs.clone(), || Ok(limb), mode)?;
            Self::to_bit_array(&limb, chunk.len())?;
            limbs.push(BitsVar(
                limb,
                (BigUint::one() << chunk.len()) - BigUint::one(),
            ));
        }

        Ok(Self(limbs))
    }
}

impl<F: PrimeField, const W: usize> R1CSVar<F> for BigUintVar<F, W> {
    type Value = BigUint;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.0.cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        let mut r = BigUint::zero();

        for limb in self.0.value()?.into_iter().rev() {
            r <<= W;
            r += Into::<BigUint>::into(limb);
        }

        Ok(r)
    }
}

impl<F: PrimeField, const W: usize> BigUintVar<F, W> {
    pub fn constant(v: BigUint, w: usize) -> Result<Self, SynthesisError> {
        Self::new_constant(ConstraintSystemRef::None, (v, w))
    }

    pub fn enforce_lt(&self, other: &Self) -> Result<(), SynthesisError> {
        let len = max(self.0.len(), other.0.len());
        let zero = BitsVar(FpVar::zero(), BigUint::zero());

        let mut delta = vec![];
        for i in 0..len {
            delta.push(&other.0.get(i).unwrap_or(&zero).0 - &self.0.get(i).unwrap_or(&zero).0);
        }

        let helper = {
            let cs = self.cs().or(other.cs());
            let mut helper = vec![false; len];
            for i in (0..len).rev() {
                let x = self.0.get(i).unwrap_or(&zero).value().unwrap_or_default();
                let y = other.0.get(i).unwrap_or(&zero).value().unwrap_or_default();
                if y > x {
                    helper[i] = true;
                    break;
                }
            }
            if cs.is_none() {
                Vec::<Boolean<F>>::new_constant(cs, helper)?
            } else {
                Vec::new_witness(cs, || Ok(helper))?
            }
        };

        let mut c = FpVar::<F>::zero();
        let mut r = FpVar::zero();
        for (b, d) in helper.into_iter().zip(delta) {
            c += b.select(&d, &FpVar::zero())?;
            (&r * &d).enforce_equal(&FpVar::zero())?;
            r += FpVar::from(b);
        }
        Self::to_bit_array(&(c - FpVar::one()), W)?;
        r.enforce_equal(&FpVar::one())?;

        Ok(())
    }

    fn to_bit_array(x: &FpVar<F>, length: usize) -> Result<Vec<Boolean<F>>, SynthesisError> {
        let cs = x.cs();

        let bits = &x.value().unwrap_or_default().into_bigint().to_bits_le()[..length];
        let bits = if cs.is_none() {
            Vec::new_constant(cs, bits)?
        } else {
            Vec::new_witness(cs, || Ok(bits))?
        };

        Boolean::le_bits_to_fp(&bits)?.enforce_equal(x)?;

        Ok(bits)
    }
}
pub struct SchnorrGadget {}

impl SchnorrGadget {
    pub fn verify<
        const W: usize,
        C: CurveGroup<BaseField: PrimeField + Absorb>,
        CVar: CurveVar<C, C::BaseField>,
    >(
        pp: &CRHParametersVar<C::BaseField>,
        pk: CVar,
        m: FpVar<C::BaseField>,
        (s, e): (Vec<Boolean<C::BaseField>>, Vec<Boolean<C::BaseField>>),
    ) -> Result<(), SynthesisError> {
        let len = C::ScalarField::MODULUS_BIT_SIZE as usize;

        assert_eq!(e.len(), len);
        assert_eq!(s.len(), len);

        let g = CVar::constant(C::generator());
        let r = g.scalar_mul_le(s.iter())? + pk.scalar_mul_le(e.iter())?;
        
        let mut xy = r.to_constraint_field()?;
        xy.pop();
        xy.push(m);

        let h = CRHGadget::evaluate(pp, &xy)?;
        let mut h_bits = h.to_bits_le()?;
        h_bits.truncate(len);

        BigUintVar::<C::BaseField, W>(h_bits.chunks(W).map(BitsVar::from).collect()).enforce_lt(
            &BigUintVar::constant(
                C::ScalarField::MODULUS.into(),
                len,
            )?,
        )?;

        Boolean::le_bits_to_fp(&h_bits[..len - 1])?.enforce_equal(&Boolean::le_bits_to_fp(&e[..len - 1])?)?;
        h_bits[len - 1].enforce_equal(&e[len - 1])?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, iter::FromIterator};

    use crate::primitives::schnorr::Schnorr;

    use super::*;
    use ark_ff::{BigInteger, UniformRand};
    use ark_bn254::{Fr, Fq};
    use ark_grumpkin::{Projective, constraints::GVar};
    use ark_r1cs_std::prelude::AllocVar;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::rand::thread_rng;
    use num::{BigUint, Zero};

    const W: usize = 32;

    pub const WIDTH: usize = 5;
    pub const R_F: usize = 8;
    pub const R_P: usize = 60;
    pub const ALPHA: u64 = 5;

    fn get_poseidon_parameters<F: PrimeField>() -> (Vec<Vec<F>>, Vec<Vec<F>>) {
        const FIELD_TYPE: u16 = 1;
        const S_BOX_TYPE: u32 = 0;
        let m: BigUint = F::MODULUS.into();
        let m_bits = F::MODULUS_BIT_SIZE;

        let mut bits = format!(
            "{FIELD_TYPE:02b}{S_BOX_TYPE:04b}{m_bits:012b}{WIDTH:012b}{R_F:010b}{R_P:010b}{}",
            "1".repeat(30)
        )
        .chars()
        .map(|i| i == '1')
        .collect::<Vec<_>>();

        let mut round = || -> bool {
            let b = bits[62] ^ bits[51] ^ bits[38] ^ bits[23] ^ bits[13] ^ bits[0];
            bits.remove(0);
            bits.push(b);
            b
        };

        for _ in 0..160 {
            round();
        }

        let mut rng = || -> BigUint {
            (0..m_bits).rev().fold(BigUint::zero(), |mut v, i| loop {
                if round() {
                    v.set_bit(i.into(), round());
                    break v;
                }
                round();
            })
        };

        let round_constants = (0..R_F + R_P)
            .map(|_| {
                (0..WIDTH)
                    .map(|_| loop {
                        let r = rng();
                        if r < m {
                            return F::from(r);
                        }
                    })
                    .collect()
            })
            .collect();

        let mds_matrix = loop {
            let v = (0..WIDTH * 2).map(|_| F::from(rng())).collect::<Vec<_>>();

            if HashSet::<F>::from_iter(v.clone()).len() == WIDTH * 2 {
                let (x, y) = v.split_at(WIDTH);
                break x
                    .iter()
                    .map(|i| y.iter().map(|j| i.add(j).inverse()).collect())
                    .collect::<Option<_>>()
                    .unwrap();
            }
        };
        (round_constants, mds_matrix)
    }

    #[test]
    fn test_native() {
        let rng = &mut thread_rng();
        let (ark, mds) = get_poseidon_parameters::<Fr>();

        let pp = PoseidonConfig::<Fr>::new(R_F, R_P, ALPHA, mds, ark, WIDTH - 1, 1);
        let (sk, pk) = Schnorr::key_gen::<Projective>(rng);
        let m = Fr::rand(rng);
        let (s, e) = Schnorr::sign::<Projective>(&pp, sk, m, rng).unwrap();
        assert!(Schnorr::verify(&pp, &pk, m, (s, e)).unwrap());
    }

    #[test]
    fn test_circuit() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let rng = &mut thread_rng();
        let (ark, mds) = get_poseidon_parameters::<Fr>();

        let pp = PoseidonConfig::<Fr>::new(R_F, R_P, ALPHA, mds, ark, WIDTH - 1, 1);
        let (sk, pk) = Schnorr::key_gen::<Projective>(rng);
        let m = Fr::rand(rng);
        let (s, e) = Schnorr::sign::<Projective>(&pp, sk, m, rng).unwrap();
        assert!(Schnorr::verify(&pp, &pk, m, (s, e)).unwrap());

        let pp = CRHParametersVar::new_constant(cs.clone(), pp).unwrap();
        let pk = GVar::new_witness(cs.clone(), || Ok(pk)).unwrap();
        let m = FpVar::new_witness(cs.clone(), || Ok(m)).unwrap();
        let s_bits = s.into_bigint().to_bits_le();
        let e_bits = e.into_bigint().to_bits_le();
        let s = Vec::new_witness(cs.clone(), || Ok(&s_bits[..Fq::MODULUS_BIT_SIZE as usize])).unwrap();
        let e = Vec::new_witness(cs.clone(), || Ok(&e_bits[..Fq::MODULUS_BIT_SIZE as usize])).unwrap();
        SchnorrGadget::verify::<W, _, _>(&pp, pk, m, (s, e)).unwrap();

        println!("{}", cs.num_constraints());
        assert!(cs.is_satisfied().unwrap());
    }
}
