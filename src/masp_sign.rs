// masp_sign is private in namada-sdk, so we need to copy it here to use it
// This is the real software-based implementation, not hardware wallet stubs
use std::collections::HashMap;
use std::ops::Deref;

use anyhow::Result;
use masp_primitives::{
    sapling::{redjubjub::PrivateKey, spend_sig},
    transaction::{
        components::sapling::{Authorization, Authorized, MapAuth},
        sighash::{signature_hash, SignableInput},
        txid::TxIdDigester,
    },
    zip32,
};
use namada_sdk::{
    masp::partial_deauthorize,
    masp_primitives::transaction::components::sapling::builder::BuildParams as BuildParamsTrait,
    signing::SigningTxData,
    tx::{Section, Tx},
    ExtendedSpendingKey,
};
use rand::rngs::OsRng;

// A mapper that replaces authorization signatures with those in a built-in map
pub struct MapSaplingSigAuth(pub HashMap<usize, <Authorized as Authorization>::AuthSig>);

impl MapAuth<Authorized, Authorized> for MapSaplingSigAuth {
    fn map_proof(
        &self,
        p: <Authorized as Authorization>::Proof,
        _pos: usize,
    ) -> <Authorized as Authorization>::Proof {
        p
    }

    fn map_auth_sig(
        &self,
        s: <Authorized as Authorization>::AuthSig,
        pos: usize,
    ) -> <Authorized as Authorization>::AuthSig {
        self.0.get(&pos).cloned().unwrap_or(s)
    }

    fn map_authorization(&self, a: Authorized) -> Authorized {
        a
    }
}

/// Sign the given transaction's MASP component using real cryptographic signatures.
/// This is the software wallet implementation that actually signs with spending keys.
pub async fn masp_sign<T>(
    tx: &mut Tx,
    signing_data: &SigningTxData,
    mut bparams: T,
    xsk: ExtendedSpendingKey,
) -> Result<()>
where
    T: BuildParamsTrait,
{
    // Get the MASP section that is the target of our signing
    if let Some(shielded_hash) = signing_data.shielded_hash {
        let mut masp_tx = tx
            .get_masp_section(&shielded_hash)
            .expect("Expected to find the indicated MASP Transaction")
            .clone();
        let masp_builder = tx
            .get_masp_builder(&shielded_hash)
            .expect("Expected to find the indicated MASP Builder");

        // Reverse the spend metadata to enable looking up construction
        // material
        let sapling_inputs = masp_builder.builder.sapling_inputs();
        let mut descriptor_map = vec![0; sapling_inputs.len()];
        for i in 0.. {
            if let Some(pos) = masp_builder.metadata.spend_index(i) {
                descriptor_map[pos] = i;
            } else {
                break;
            };
        }

        let tx_data = masp_tx.deref();

        let unauth_tx_data = partial_deauthorize(tx_data)
            .ok_or_else(|| anyhow::anyhow!("Failed to deauthorize transaction"))?;

        let txid_parts = unauth_tx_data.digest(TxIdDigester);
        let sighash = signature_hash(&unauth_tx_data, &SignableInput::Shielded, &txid_parts);

        let mut authorizations = HashMap::new();
        for (tx_pos, _) in descriptor_map.iter().enumerate() {
            // Extract the spend authorization key from the extended spending key
            let pk = PrivateKey(zip32::ExtendedSpendingKey::from(xsk).expsk.ask);
            let mut rng = OsRng;

            // Generate the actual cryptographic signature
            let sig = spend_sig(pk, bparams.spend_alpha(tx_pos), sighash.as_ref(), &mut rng);

            authorizations.insert(tx_pos, sig);
        }

        // Apply the real signatures to the transaction
        masp_tx = (*masp_tx)
            .clone()
            .map_authorization::<masp_primitives::transaction::Authorized>(
                (),
                MapSaplingSigAuth(authorizations),
            )
            .freeze()
            .map_err(|e| anyhow::anyhow!("Failed to freeze transaction: {}", e))?;

        tx.remove_masp_section(&shielded_hash);
        tx.add_section(Section::MaspTx(masp_tx));
    }
    Ok(())
}
