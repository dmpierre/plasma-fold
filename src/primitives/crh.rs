// Define the various CRH used in PlasmaFold
use std::{borrow::Borrow, marker::PhantomData};

use ark_crypto_primitives::{
    crh::CRHScheme,
    sponge::{
        poseidon::{PoseidonConfig, PoseidonSponge},
        Absorb, CryptographicSponge,
    },
    Error,
};
use ark_ff::PrimeField;
use ark_std::rand::Rng;

use crate::datastructures::{transaction::Transaction, utxo::UTXO};

// computes H(transaction)
pub struct TransactionCRH<F: PrimeField + Absorb> {
    _f: PhantomData<F>,
}

// computes H(UTXO)
pub struct UTXOCRH<F: PrimeField + Absorb> {
    _f: PhantomData<F>,
}

impl<F: PrimeField + Absorb> CRHScheme for TransactionCRH<F> {
    type Input = Transaction<F>;
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

impl<F: PrimeField + Absorb> CRHScheme for UTXOCRH<F> {
    type Input = UTXO<F>;
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
        sponge.absorb(&input.as_ref());
        let res = sponge.squeeze_field_elements::<F>(1);
        Ok(res[0])
    }
}
