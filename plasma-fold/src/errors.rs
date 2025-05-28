use thiserror::Error;

#[derive(Error, Debug)]
pub enum TransactionError {
    #[error("Invalid nonce for transaction expected {0}, got: {1}")]
    InvalidNonce(u64, u64),
    #[error("Inputs do not sum with outputs")]
    InvalidAmounts,
    #[error("Inputs pk are not equal to the sender pk")]
    InvalidPublicKey,
    #[error("Failed to build transaction tree")]
    TransactionTreeFailure,
}
