// Define the various CRH used in PlasmaFold
use crate::datastructures::{keypair::PublicKey, noncemap::Nonce, transaction::Transaction};
use ark_crypto_primitives::{
    crh::{poseidon::CRH, CRHScheme},
    sponge::{
        poseidon::{PoseidonConfig, PoseidonSponge},
        Absorb, CryptographicSponge,
    },
    Error,
};
use ark_ec::CurveGroup;
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
        let mut elements = Vec::new();
        input.borrow().to_sponge_field_elements(&mut elements);
        let res = CRH::evaluate(parameters, elements.as_slice())?;
        Ok(res)
    }
}

pub struct PublicKeyCRH<F: PrimeField + Absorb, C: CurveGroup<ScalarField = F>> {
    _f: PhantomData<F>,
    _f1: PhantomData<C>,
}

impl<F: PrimeField + Absorb, C: CurveGroup<ScalarField = F>> CRHScheme for PublicKeyCRH<F, C>
where
    C::BaseField: Absorb,
{
    type Input = PublicKey<C>;
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
        let input = input.borrow();
        let mut sponge = PoseidonSponge::new(parameters);
        sponge.absorb(&input);
        let res = sponge.squeeze_field_elements::<F>(1);
        Ok(res[0])
    }
}

pub struct NonceCRH<F: PrimeField + Absorb> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> CRHScheme for NonceCRH<F>
{
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
        let input = input.borrow();
        let mut sponge = PoseidonSponge::new(parameters);
        sponge.absorb(&input);
        let res = sponge.squeeze_field_elements::<F>(1);
        Ok(res[0])
    }
}
