use std::collections::HashMap;

use ark_crypto_primitives::crh::sha256::{digest::Digest, Sha256};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField, ToConstraintField, Zero};
use folding_schemes::{folding::nova::IVCProof, Curve};
use plasma_fold::datastructures::{block::Block, keypair::PublicKey, noncemap::Nonce};

#[derive(Debug, Clone, Copy)]
pub struct L1Account {
    pub balance: u64,
}

impl L1Account {
    pub fn new(balance: u64) -> Self {
        Self { balance }
    }

    pub fn transfer(&mut self, other: &mut Self, amount: u64) {
        assert!(self.balance >= amount);
        self.balance -= amount;
        other.balance += amount;
    }
}

pub struct MockContract<C: CurveGroup> {
    pub pks: Vec<PublicKey<C>>,
    pub pk_indices: HashMap<PublicKey<C>, usize>,
    pub l1_accounts: Vec<L1Account>,
    pub nonces: Vec<Nonce>,

    pub block_hashes: Vec<C::BaseField>,

    /// A queue (not really) of deposits, mapping public keys to the pending deposit amounts.
    pub deposits: HashMap<PublicKey<C>, u64>,
}

impl<C: CurveGroup> MockContract<C> {
    pub fn new(contract_pk: PublicKey<C>) -> Self {
        let mut state = Self {
            pks: vec![],
            pk_indices: HashMap::new(),
            l1_accounts: vec![],
            nonces: vec![],
            block_hashes: vec![],
            deposits: HashMap::new(),
        };
        // Enroll the contract itself
        state.join(L1Account::new(0), contract_pk);
        state
    }

    /// Invoked by the user when they join the L2, registering their public key.
    pub fn join(&mut self, l1_account: L1Account, pk: PublicKey<C>) -> usize {
        let index = self.pks.len();
        self.pks.push(pk);
        self.pk_indices.insert(pk, index);
        self.l1_accounts.push(l1_account);
        self.nonces.push(Nonce(0));
        index
    }

    /// Invoked by the user who wants to deposit L1 funds into the contract in exchange for L2 funds.
    pub fn deposit(&mut self, index: usize, amount: u64) {
        let (l, r) = self.l1_accounts.split_at_mut(index);
        r[0].transfer(&mut l[0], amount);
        self.deposits
            .entry(self.pks[index])
            .and_modify(|e| *e += amount)
            .or_insert(amount);
    }

    pub fn add_block(&mut self, _block: Block<C::BaseField>) {
        unimplemented!("Unnecessary for now")
    }

    pub fn derive_public_inputs(&self, block: Block<C::BaseField>) -> Vec<C::BaseField>
    where
        C::BaseField: PrimeField,
    {
        let step = C::BaseField::from(block.signers.len() as u64);
        let utxo_root = block.utxo_tree_root;
        let tx_root = block.tx_tree_root;
        let tx_root_final = block.tx_tree_root;
        let signer_root = block.signer_tree_root;

        let mut signer_acc = C::BaseField::zero();
        for &index in &block.signers {
            let pk = if let Some(i) = index {
                self.pks[i as usize].key
            } else {
                C::zero()
            };
            let affine = pk.into_affine();
            signer_acc = Sha256::digest(
                [
                    signer_acc.into_bigint().to_bytes_le(),
                    affine.x().unwrap_or_default().into_bigint().to_bytes_le(),
                    affine.y().unwrap_or_default().into_bigint().to_bytes_le(),
                    vec![affine.is_zero() as u8],
                ]
                .concat(),
            )[..31]
                .to_field_elements()
                .unwrap()[0];
        }

        let mut deposit_acc = C::BaseField::zero();
        for &(index, amount) in &block.deposits {
            let pk = self.pks[index as usize];
            let affine = pk.key.into_affine();
            deposit_acc = Sha256::digest(
                [
                    deposit_acc.into_bigint().to_bytes_le(),
                    affine.x().unwrap_or_default().into_bigint().to_bytes_le(),
                    affine.y().unwrap_or_default().into_bigint().to_bytes_le(),
                    vec![affine.is_zero() as u8],
                    amount.to_le_bytes().to_vec(),
                ]
                .concat(),
            )[..31]
                .to_field_elements()
                .unwrap()[0];
        }
        let mut withdrawal_acc = C::BaseField::zero(); // Placeholder for withdrawal accumulator
        for &(index, amount) in &block.withdrawals {
            let pk = self.pks[index as usize];
            let affine = pk.key.into_affine();
            withdrawal_acc = Sha256::digest(
                [
                    withdrawal_acc.into_bigint().to_bytes_le(),
                    affine.x().unwrap_or_default().into_bigint().to_bytes_le(),
                    affine.y().unwrap_or_default().into_bigint().to_bytes_le(),
                    vec![affine.is_zero() as u8],
                    amount.to_le_bytes().to_vec(),
                ]
                .concat(),
            )[..31]
                .to_field_elements()
                .unwrap()[0];
        }

        vec![
            step,
            utxo_root,
            tx_root,
            tx_root_final,
            signer_root,
            signer_acc,
            deposit_acc,
            withdrawal_acc,
        ]
    }
}

impl<C2: Curve> MockContract<C2> {
    pub fn verify_proof<C1: Curve>(_proof: IVCProof<C1, C2>) {
        unimplemented!("Unnecessary for now")
    }
}
