use thiserror::Error;

#[derive(Error, Debug)]
pub enum AggregatorError {
    #[error("Invalid CRH evaluation for transaction")]
    TransactionCRHError,
    #[error("Invalid signature for transaction")]
    SignatureError,
    #[error("Invalid utxo")]
    UTXOError,
    #[error("Invalid utxo tree update")]
    UTXOTreeUpdateError,
}
