// masp_sign is private in namada-sdk, so we need to copy it here to use it
use anyhow::Result;
use masp_primitives::transaction::components::sapling::{self};
use namada_sdk::{
    args,
    signing::SigningTxData,
    tx::{Section, Tx},
};
use std::collections::HashMap;

// A mapper that replaces authorization signatures with those in a built-in map
// Note: This struct is only used for hardware wallet MASP signing, but we're keeping it
// to maintain the same implementation as the original masp_sign function from namada
#[allow(dead_code)]
struct MapSaplingSigAuth(HashMap<usize, <sapling::Authorized as sapling::Authorization>::AuthSig>);

impl sapling::MapAuth<sapling::Authorized, sapling::Authorized> for MapSaplingSigAuth {
    fn map_proof(
        &self,
        p: <sapling::Authorized as sapling::Authorization>::Proof,
        _pos: usize,
    ) -> <sapling::Authorized as sapling::Authorization>::Proof {
        p
    }

    fn map_auth_sig(
        &self,
        s: <sapling::Authorized as sapling::Authorization>::AuthSig,
        pos: usize,
    ) -> <sapling::Authorized as sapling::Authorization>::AuthSig {
        self.0.get(&pos).cloned().unwrap_or(s)
    }

    fn map_authorization(&self, a: sapling::Authorized) -> sapling::Authorized {
        a
    }
}

/// Sign the given transaction's MASP component using signatures produced by the
/// hardware wallet. This function takes the list of spending keys that are
/// hosted on the hardware wallet.
pub async fn masp_sign(
    tx: &mut Tx,
    _args: &args::Tx,
    signing_data: &SigningTxData,
    shielded_hw_keys: HashMap<String, namada_core::masp::ExtendedViewingKey>,
) -> Result<()> {
    // Get the MASP section that is the target of our signing
    if let Some(shielded_hash) = signing_data.shielded_hash {
        let masp_tx = tx
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

        // For software wallet usage (no hardware wallet), we still need to handle
        // the MASP transaction structure, but hardware wallet signing is skipped
        if !shielded_hw_keys.is_empty() {
            println!("   ⚠️  Hardware wallet MASP signing not implemented in this example");
            println!(
                "   📝 Would handle {} hardware wallet keys",
                shielded_hw_keys.len()
            );
        }

        // The transaction should already have proper authorization signatures
        // from the build process when using fake spend authorization keys
        tx.remove_masp_section(&shielded_hash);
        tx.add_section(Section::MaspTx(masp_tx));
    }
    Ok(())
}
