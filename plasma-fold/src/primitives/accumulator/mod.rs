use ark_crypto_primitives::{
    crh::{sha256::Sha256, TwoToOneCRHScheme},
    Error,
};
use ark_ff::{BigInteger, PrimeField};

pub mod constraints;

// to avoid overflowing the field, we split our accumulator into two field elements
pub struct Sha256Accumulator<F: PrimeField>(pub F);

impl<F: PrimeField + BigInteger> Sha256Accumulator<F> {
    pub fn update(&mut self, value: F) -> Result<(), Error> {
        let right_input = value.to_bytes_le();
        let left_input = self.0.to_bytes_le();
        let mut value = Sha256::evaluate(&(), left_input, right_input)?;
        // drop last byte
        let (_, value) = value.split_last().unwrap();
        self.0 = F::from_le_bytes_mod_order(&value);
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    #[test]
    pub fn test_accumulator_constraints() {}
}
