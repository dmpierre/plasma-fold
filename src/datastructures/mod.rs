use crate::datastructures::user::UserId;
use ark_ff::PrimeField;

pub mod transaction;
pub mod user;
pub mod utxo;

// max number of input/output utxos in a transaction
// |tx_inputs| + |tx_outputs| == TX_IO_SIZE * 2
pub const TX_IO_SIZE: usize = 4;
pub const TX_ARRAY_SIZE: usize = TX_IO_SIZE * 4 + 1;

pub type SignerList<F: PrimeField> = Vec<UserId<F>>;
