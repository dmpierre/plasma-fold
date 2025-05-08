use ark_crypto_primitives::merkle_tree::Config;

// contains the roots of utxo, transaction, signer, deposit and withdraw trees
pub struct Block<U: Config, T: Config, S: Config, D: Config, W: Config> {
    pub utxo_tree_root: U::InnerDigest,
    pub tx_tree_root: T::InnerDigest,
    pub signer_tree_root: S::InnerDigest,
    pub deposit_tree_root: D::InnerDigest,
    pub withdraw_tree_root: W::InnerDigest,
}
