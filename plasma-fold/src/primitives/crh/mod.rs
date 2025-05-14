// Define the various CRH used in PlasmaFold
use crate::datastructures::{
    keypair::PublicKey, noncemap::Nonce, transaction::Transaction, user::UserId, utxo::UTXO,
};
use ark_crypto_primitives::{
    crh::{poseidon::CRH, CRHScheme},
    sponge::{poseidon::PoseidonConfig, Absorb},
    Error,
};
use ark_ec::AdditiveGroup;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use std::{borrow::Borrow, marker::PhantomData};

pub mod constraints;

// computes H(transaction)
pub struct TransactionCRH<F: PrimeField + Absorb> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> CRHScheme for TransactionCRH<F> {
    type Input = Transaction;
    type Output = F;
    type Parameters = PoseidonConfig<F>;

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        // automatic generation of parameters are not implemented yet
        // therefore, the developers must specify the parameters themselves
        unimplemented!()
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let tx: &Transaction = input.borrow();
        let elements: Vec<F> = tx.into();
        let res = CRH::evaluate(parameters, elements.as_slice())?;
        Ok(res)
    }
}

pub struct PublicKeyCRH<C: CurveGroup> {
    _c: PhantomData<C>,
}

impl<C: CurveGroup<BaseField: PrimeField + Absorb>> CRHScheme for PublicKeyCRH<C> {
    type Input = PublicKey<C>;
    type Output = C::BaseField;
    type Parameters = PoseidonConfig<C::BaseField>;

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        // automatic generation of parameters are not implemented yet
        // therefore, the developers must specify the parameters themselves
        unimplemented!()
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let input: &PublicKey<C> = input.borrow();
        let point = input.key.into_affine();
        if point.is_zero() {
            Ok(CRH::evaluate(
                parameters,
                // flag for point is zero is true
                [C::BaseField::ZERO, C::BaseField::ZERO, C::BaseField::ONE],
            )?)
        } else {
            let (x, y) = point.xy().unwrap();
            // flag for point is zero is false
            Ok(CRH::evaluate(parameters, [x, y, C::BaseField::ZERO])?)
        }
    }
}

pub struct NonceCRH<F: PrimeField + Absorb> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb + From<Nonce>> CRHScheme for NonceCRH<F> {
    type Input = [Nonce];
    type Output = F;
    type Parameters = PoseidonConfig<F>;

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        // automatic generation of parameters are not implemented yet
        // therefore, the developers must specify the parameters themselves
        unimplemented!()
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let input = F::from(input.borrow()[0]);
        Ok(CRH::evaluate(parameters, [input])?)
    }
}

pub struct UserIdCRH<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb + From<UserId>> CRHScheme for UserIdCRH<F> {
    type Input = [UserId];
    type Output = F;
    type Parameters = PoseidonConfig<F>;

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        // automatic generation of parameters are not implemented yet
        // therefore, the developers must specify the parameters themselves
        unimplemented!()
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let input = F::from(input.borrow()[0]);
        Ok(CRH::evaluate(parameters, [input])?)
    }
}

pub struct UTXOCRH<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> CRHScheme for UTXOCRH<F> {
    type Input = UTXO;
    type Output = F;
    type Parameters = PoseidonConfig<F>;

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        // automatic generation of parameters are not implemented yet
        // therefore, the developers must specify the parameters themselves
        unimplemented!()
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let utxo: &UTXO = input.borrow();
        let input = [F::from(utxo.amount), F::from(utxo.id)];
        Ok(CRH::evaluate(parameters, input)?)
    }
}

#[cfg(test)]
pub mod tests {
    use ark_bn254::Fr;
    use ark_crypto_primitives::crh::{
        poseidon::constraints::CRHParametersVar, CRHScheme, CRHSchemeGadget,
    };
    use ark_ff::UniformRand;
    use ark_grumpkin::{constraints::GVar, Projective};
    use ark_r1cs_std::{alloc::AllocVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::rand::thread_rng;
    use folding_schemes::transcript::poseidon::poseidon_canonical_config;

    use crate::{
        datastructures::keypair::{constraints::PublicKeyVar, PublicKey},
        primitives::crh::{constraints::PublicKeyVarCRH, PublicKeyCRH},
    };

    #[test]
    pub fn test_public_key_crh() {
        let mut rng = thread_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let pp = poseidon_canonical_config();
        let pp_var = CRHParametersVar::new_constant(cs.clone(), &pp).unwrap();

        for i in 0..20 {
            let key = if i == 0 {
                Projective::default() // zero point
            } else {
                Projective::rand(&mut rng)
            };
            let public_key = PublicKey { key };
            let public_key_var =
                PublicKeyVar::<Projective, GVar>::new_witness(
                    cs.clone(),
                    || Ok(public_key.clone()),
                )
                .unwrap();

            let res1 = PublicKeyCRH::evaluate(&pp, &public_key).unwrap();
            let res2 = PublicKeyVarCRH::evaluate(&pp_var, &public_key_var).unwrap();
            assert_eq!(res1, res2.value().unwrap());
        }
    }
}
