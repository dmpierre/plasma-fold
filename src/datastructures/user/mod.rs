use ark_ff::PrimeField;

pub type UserId<F: PrimeField> = F;

pub struct User<F> {
    id: UserId<F>,
}
