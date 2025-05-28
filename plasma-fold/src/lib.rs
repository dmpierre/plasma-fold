#![feature(error_generic_member_access)]
pub mod circuits;
pub mod datastructures;
pub mod errors;
pub mod primitives;

const TX_TREE_HEIGHT: u64 = 13;
const SIGNER_TREE_HEIGHT: u64 = TX_TREE_HEIGHT;
