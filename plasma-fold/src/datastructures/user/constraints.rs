use ark_ec::CurveGroup;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};

use super::User;

pub struct UserVar<C: CurveGroup> {
    pub state: Vec<FpVar<C::ScalarField>>,
}

// z_i is (balance, nonce, acc)
// z_i is a vec of FpVar<F> in sonobe
impl<C: CurveGroup> AllocVar<User<C>, C::ScalarField> for UserVar<C> {
    fn new_variable<T: std::borrow::Borrow<User<C>>>(
        cs: impl Into<ark_relations::gr1cs::Namespace<C::ScalarField>>,
        f: impl FnOnce() -> Result<T, ark_relations::gr1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::gr1cs::SynthesisError> {
        let res = f()?;
        let user = res.borrow();
        let cs = cs.into().cs();
        let balance =
            FpVar::new_variable(cs.clone(), || Ok(C::ScalarField::from(user.balance)), mode)?;
        let nonce =
            FpVar::new_variable(cs.clone(), || Ok(C::ScalarField::from(user.nonce.0)), mode)?;
        let acc = FpVar::new_variable(cs.clone(), || Ok(user.acc), mode)?;
        Ok(Self {
            state: Vec::from([balance, nonce, acc]),
        })
    }
}
