use ark_r1cs_std::fields::fp::FpVar;

pub type UserId = u32;
pub type UserIdVar<F> = FpVar<F>;

pub struct User {
    id: UserId,
}
