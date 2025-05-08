pub mod block;
pub mod deposits;
pub mod keypair;
pub mod noncemap;
pub mod publickeymap;
pub mod signerlist;
pub mod transaction;
pub mod user;
pub mod utxo;
pub mod withdrawals;

// max number of input/output utxos in a transaction
// |tx_inputs| + |tx_outputs| == TX_IO_SIZE * 2
pub const TX_IO_SIZE: usize = 4;
pub const TX_ARRAY_SIZE: usize = TX_IO_SIZE * 4 + 1;

pub const USER_ID_ROLLUP: usize = 0;
