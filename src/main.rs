use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Local};
use namada_core::{
    address::Address,
    chain::ChainId,
    ibc::core::host::types::identifiers::{ChannelId, PortId},
    masp::TransferSource,
};
use namada_sdk::{
    args::{DeviceTransport, InputAmount, Tx as TxArgs, TxExpiration, TxIbcTransfer},
    control_flow::install_shutdown_signal,
    io::NullIo,
    masp::{
        fs::FsShieldedUtils, IndexerMaspClient, MaspLocalTaskEnv, ShieldedContext,
        ShieldedSyncConfig,
    },
    token::{Amount, DenominatedAmount},
    wallet::{fs::FsWalletUtils, DatedKeypair},
    ExtendedSpendingKey, Namada, NamadaImpl, TransferTarget,
};
use namada_tx::data::GasLimit;
use rand::rngs::OsRng;
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    path::PathBuf,
    str::FromStr,
    time::Duration,
};
use tendermint_rpc::{Client, HttpClient, Url as TendermintUrl};
use tracing::info;
use url::Url;

// Import MASP primitives directly
use masp_primitives::{
    sapling::redjubjub,
    transaction::components::sapling::builder::RngBuildParams,
    zip32::{ExtendedKey, ExtendedSpendingKey as MaspExtendedSpendingKey, PseudoExtendedKey},
};

// Import StoredBuildParams
use masp_primitives::transaction::components::sapling::builder::StoredBuildParams;

// Additional imports for masp_sign function
// (HashMap no longer needed since we're using direct xsk approach)

// Module declarations
mod masp_sign;
use masp_sign::masp_sign;

// Constants
const NAM_TOKEN_ADDRESS: &str = "tnam1q9gr66cvu4hrzm0sd5kmlnjje82gs3xlfg3v6nu7";
const MASP_INDEXER_URLS: &[&str] = &[
    "https://masp-namada.5elementsnodes.com/api/v1",
    "https://masp-indexer.papadritta.com/api/v1",
    "https://namada-masp.nodes.guru/api/v1",
    "https://masp.namada.validatus.com/api/v1",
    "https://namada-masp-indexer.0xcryptovestor.com/api/v1",
    "https://masp-indexer.namada.stakeup.tech/api/v1",
    "https://namada-mainnet-masp-indexer.crouton.digital/api/v1",
];

/// Simple function to check if MASP parameters exist locally
fn check_masp_params_exist() -> Result<bool> {
    let masp_dir = std::path::Path::new("./masp-params");
    if !masp_dir.exists() {
        return Ok(false);
    }

    let required_files = [
        "masp-spend.params",
        "masp-output.params",
        "masp-convert.params",
    ];

    for file in &required_files {
        let path = masp_dir.join(file);
        if !path.exists() {
            return Ok(false);
        }
    }

    info!("✅ All MASP parameters found locally");
    Ok(true)
}

/// Simple function to get native token address
fn get_native_token_address() -> Result<Address> {
    Address::from_str(NAM_TOKEN_ADDRESS).context("Failed to parse native token address")
}

/// Simple function to create wallet ID from viewing key
fn create_wallet_id_from_viewing_key(viewing_key: &str) -> String {
    let mut hasher = DefaultHasher::new();
    viewing_key.hash(&mut hasher);
    let hash = hasher.finish();
    format!("wallet_{hash:x}")
}

/// Generate a disposable signing key and return both the secret key and public key
async fn gen_disposable_signing_key_pair(
    context: &impl Namada,
) -> (
    namada_core::key::common::SecretKey,
    namada_core::key::common::PublicKey,
) {
    let secret_key = context
        .wallet_mut()
        .await
        .gen_disposable_signing_key(&mut OsRng);
    let public_key = secret_key.to_public();
    (secret_key, public_key)
}

/// Get current timestamp in readable format
fn get_timestamp() -> String {
    let now: DateTime<Local> = Local::now();
    now.format("%H:%M:%S%.3f").to_string()
}

/// Simple function to initialize Namada SDK
async fn initialize_sdk(
    rpc_url: String,
    wallet_id: Option<String>,
) -> Result<NamadaImpl<HttpClient, FsWalletUtils, FsShieldedUtils, NullIo>> {
    info!("Initializing Namada SDK components");

    // Create RPC client
    let rpc_url = TendermintUrl::from_str(&rpc_url).context("Invalid RPC URL")?;
    let rpc_client = HttpClient::new(rpc_url).context("Failed to create RPC client")?;

    // Create wallet utils with persistent directory
    let wallet_dir = if let Some(wallet_id) = &wallet_id {
        let base_dir = std::env::current_dir()
            .context("Failed to get current directory")?
            .join("wallet-cache")
            .join(wallet_id);
        std::fs::create_dir_all(&base_dir)
            .with_context(|| format!("Failed to create wallet directory: {base_dir:?}"))?;
        base_dir
    } else {
        let temp_dir = std::env::temp_dir().join("simple-ibc-tx-wallet");
        std::fs::create_dir_all(&temp_dir)
            .with_context(|| format!("Failed to create temp wallet directory: {temp_dir:?}"))?;
        temp_dir
    };
    let wallet_utils = FsWalletUtils::new(wallet_dir);

    // Create shielded utils with per-wallet persistent directory
    let shielded_dir = if let Some(wallet_id) = &wallet_id {
        let wallet_masp_dir = std::env::current_dir()
            .context("Failed to get current directory")?
            .join("masp-cache")
            .join(wallet_id);
        std::fs::create_dir_all(&wallet_masp_dir).with_context(|| {
            format!("Failed to create MASP cache directory: {wallet_masp_dir:?}")
        })?;
        wallet_masp_dir
    } else {
        std::env::current_dir()
            .context("Failed to get current directory")?
            .join("masp-params")
    };
    let shielded_utils = FsShieldedUtils::new(shielded_dir);
    let shielded_context = ShieldedContext::new(shielded_utils);

    // Get native token address
    let native_token = get_native_token_address()?;

    // Create Namada SDK instance
    let sdk = NamadaImpl::native_new(
        rpc_client,
        wallet_utils,
        shielded_context.into(),
        NullIo,
        native_token,
    );

    info!("Successfully initialized Namada SDK components");
    Ok(sdk)
}

/// Simple function to create sync configuration
async fn create_sync_config() -> Result<
    ShieldedSyncConfig<IndexerMaspClient, kdam::Bar, namada_sdk::control_flow::ShutdownSignalChan>,
> {
    info!("Creating MASP sync configuration");

    // Try first indexer URL
    let indexer_url = MASP_INDEXER_URLS[0];
    info!("Using MASP indexer: {}", indexer_url);

    // Create HTTP client
    let http_client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(60))
        .build()
        .context("Failed to create HTTP client")?;

    // Parse indexer URL
    let url = Url::parse(indexer_url)
        .with_context(|| format!("Failed to parse indexer URL: {indexer_url}"))?;

    // Create indexer client
    let indexer_client = IndexerMaspClient::new(
        http_client,
        url,
        true, // using_block_index
        1000, // max_concurrent_fetches
    );

    // Create progress bars
    let fetched_bar = kdam::tqdm!(
        total = 0,
        position = 0,
        desc = "Fetching blocks ",
        animation = "fillup",
        force_refresh = true,
        dynamic_ncols = true,
        miniters = 0,
        mininterval = 0.1
    );

    let scanned_bar = kdam::tqdm!(
        total = 0,
        position = 1,
        desc = "Scanning txs   ",
        animation = "fillup",
        force_refresh = true,
        dynamic_ncols = true,
        miniters = 0,
        mininterval = 0.1
    );

    let applied_bar = kdam::tqdm!(
        total = 0,
        position = 2,
        desc = "Applying notes ",
        animation = "fillup",
        force_refresh = true,
        dynamic_ncols = true,
        miniters = 0,
        mininterval = 0.1
    );

    // Create sync config
    let config = ShieldedSyncConfig::builder()
        .client(indexer_client)
        .fetched_tracker(fetched_bar)
        .scanned_tracker(scanned_bar)
        .applied_tracker(applied_bar)
        .shutdown_signal(install_shutdown_signal(false))
        .block_batch_size(1000)
        .channel_buffer_size(1000)
        .wait_for_last_query_height(false)
        .build();

    info!("Successfully created MASP sync configuration");
    Ok(config)
}

/// Simple function to perform MASP sync
async fn perform_masp_sync(
    sdk: &NamadaImpl<HttpClient, FsWalletUtils, FsShieldedUtils, NullIo>,
    viewing_key: String,
) -> Result<()> {
    info!("Starting MASP sync");

    // Parse viewing key
    let extended_viewing_key = namada_core::masp::ExtendedViewingKey::from_str(&viewing_key)
        .map_err(|e| anyhow!("Invalid viewing key format: {}", e))?;
    let viewing_key = extended_viewing_key.as_viewing_key();

    // Create dated viewing key for sync operations
    let dated_viewing_key = DatedKeypair {
        key: viewing_key,
        birthday: namada_core::chain::BlockHeight::from(1),
    };

    // Create sync config
    let sync_config = create_sync_config().await?;

    // Perform shielded wallet synchronization
    info!("Starting shielded wallet sync...");
    let mut shielded = sdk.shielded_mut().await;

    // Create a new env for this sync operation
    let env = MaspLocalTaskEnv::new(100)
        .map_err(|e| anyhow!("Could not create MASP environment: {}", e))?;

    let sync_result = shielded
        .sync(env, sync_config, None, &[], &[dated_viewing_key])
        .await;

    match sync_result {
        Ok(resp) => {
            info!("Shielded sync completed successfully: {:?}", resp);
        }
        Err(e) => {
            return Err(anyhow!("Sync failed: {}", e));
        }
    }

    info!("MASP sync completed successfully");
    Ok(())
}

/// Build IBC unshielding transaction (Steps 1-7) - Can be done unsecurely
async fn build_ibc_unshielding_tx(
    sdk: &NamadaImpl<HttpClient, FsWalletUtils, FsShieldedUtils, NullIo>,
    pxk: PseudoExtendedKey,
    rpc_url: String,
    wrapper_public_key: namada_core::key::common::PublicKey,
) -> Result<(
    namada_tx::Tx,
    namada_sdk::signing::SigningTxData,
    StoredBuildParams,
)> {
    info!("🚀 Building IBC Unshielding Transaction");
    println!("=======================================");
    println!("Building transaction with provided PseudoExtendedKey");
    println!();

    // Step 1: Build IBC transfer transaction
    println!(
        "📋 Step 1: Build IBC transfer transaction [{}]",
        get_timestamp()
    );

    // Get native token address
    let native_token_address = get_native_token_address()?;

    // Create transaction arguments (same structure as JS but with proper types)
    let tx_args = TxIbcTransfer {
        tx: TxArgs {
            dry_run: false,
            dry_run_wrapper: false,
            dump_tx: false,
            dump_wrapper_tx: false,
            force: false,
            broadcast_only: false,
            ledger_address: rpc_url.parse().context("Failed to parse RPC URL")?,
            wallet_alias_force: false,
            initialized_account_alias: None,
            fee_amount: Some(InputAmount::Unvalidated(DenominatedAmount::new(
                Amount::from_u64(1),
                6u8.into(),
            ))),
            fee_token: native_token_address.clone(),
            gas_limit: GasLimit::from_str("100000").context("Failed to parse gas limit")?,
            wrapper_fee_payer: Some(wrapper_public_key.clone()),
            output_folder: None,
            expiration: TxExpiration::Default,
            chain_id: Some(ChainId("namada.5f5de2dd1b88cba30586420".to_string())), // From JS
            signing_keys: vec![wrapper_public_key.clone()],
            tx_reveal_code_path: PathBuf::from("tx_reveal_pk.wasm"),
            use_device: false,
            password: None,
            memo: None,
            device_transport: DeviceTransport::default(),
        },
        source: TransferSource::ExtendedKey(pxk),
        receiver: "osmo18st0wqx84av8y6xdlss9d6m2nepyqwj6n3q7js".to_string(), // From JS
        token: Address::from_str("tnam1p5z8ruwyu7ha8urhq2l0dhpk2f5dv3ts7uyf2n75") // Osmo on Namada from JS
            .context("Failed to parse token address")?,
        amount: InputAmount::Validated(DenominatedAmount::new(
            Amount::from_string_precise("1").context("Failed to parse amount")?,
            0u8.into(),
        )),
        port_id: PortId::from_str("transfer").context("Failed to create port ID")?,
        channel_id: ChannelId::from_str("channel-1").context("Failed to create channel ID")?, // From JS
        timeout_height: None,
        timeout_sec_offset: None,
        refund_target: Some(TransferTarget::Address(
            Address::from_str("tnam1qzxjfnz6m5dhfyddnw9qvrapuqv9vxmrncckdy9l") // From JS
                .context("Failed to parse refund target")?,
        )),
        ibc_shielding_data: None,
        ibc_memo: None,
        gas_spending_key: Some(pxk),
        tx_code_path: PathBuf::from("tx_ibc.wasm"),
    };

    println!("   ✅ IBC transfer arguments created (matching JS example)");

    // Step 2: Build transaction
    println!("📋 Step 2: Build transaction [{}]", get_timestamp());

    // Create build parameters with randomness
    let mut build_params = RngBuildParams::new(OsRng);

    // Build the transaction
    let (tx, signing_data, _masp_epoch) =
        namada_sdk::tx::build_ibc_transfer(sdk, &tx_args, &mut build_params)
            .await
            .context("Failed to build IBC transfer")?;

    // Store the build parameters to preserve randomness
    let stored_build_params = build_params
        .to_stored()
        .ok_or_else(|| anyhow!("Failed to store build parameters"))?;

    println!("   ✅ IBC transfer built successfully!");
    println!("   📊 Transaction size: {} bytes", tx.to_bytes().len());
    println!("   🎲 Build parameters stored for signing");
    println!();

    Ok((tx, signing_data, stored_build_params))
}

/// Sign transaction - both MASP and wrapper (Steps 8-9) - Needs to be done securely
async fn sign_tx(
    mut tx: namada_tx::Tx,
    xsk: ExtendedSpendingKey,
    wrapper_secret_key: namada_core::key::common::SecretKey,
    signing_data: &namada_sdk::signing::SigningTxData,
    stored_build_params: StoredBuildParams,
) -> Result<namada_tx::Tx> {
    // Step 8: Sign MASP components
    println!("📋 Step 8: Sign MASP components [{}]", get_timestamp());

    // Use the stored build parameters to preserve randomness
    match masp_sign(&mut tx, signing_data, stored_build_params, xsk).await {
        Ok(()) => {
            println!("   ✅ MASP components signed successfully");
        }
        Err(e) => {
            println!("   ❌ MASP signing failed: {e}");
            return Err(anyhow!("MASP signing failed: {e}"));
        }
    }
    println!();

    // Step 9: Sign wrapper transaction
    println!("📋 Step 9: Sign wrapper transaction [{}]", get_timestamp());

    // Sign raw transaction if account public keys map is available
    if let Some(account_public_keys_map) = signing_data.account_public_keys_map.clone() {
        tx.sign_raw(
            vec![wrapper_secret_key.clone()],
            account_public_keys_map,
            signing_data.owner.clone(),
        );
        println!("   ✅ Raw transaction signed");
    }

    // Sign the wrapper
    tx.sign_wrapper(wrapper_secret_key);
    println!("   ✅ Wrapper transaction signed");
    println!();

    Ok(tx)
}

/// Broadcast transaction (Step 10) - Can be done unsecurely
async fn broadcast(tx: namada_tx::Tx, rpc_url: String) -> Result<()> {
    println!("📋 Step 10: Broadcast transaction [{}]", get_timestamp());

    let rpc_url_parsed = tendermint_rpc::Url::from_str(&rpc_url).context("Invalid RPC URL")?;
    let client = HttpClient::new(rpc_url_parsed)?;
    println!("   🚀 Broadcasting to: {rpc_url}");

    let response = client
        .broadcast_tx_sync(tx.to_bytes())
        .await
        .context("Failed to broadcast transaction")?;

    println!("   📋 Response: {response:?}");

    if response.code == 0.into() {
        println!("   ✅ Transaction broadcast successful!");
        println!("   📋 TX Hash: {}", response.hash);
        println!("   📝 Log: {}", response.log);
    } else {
        println!("   ❌ Transaction broadcast failed!");
        println!("   📋 Code: {:?}", response.code);
        println!("   📝 Log: {}", response.log);
    }

    println!();
    println!("🎉 JavaScript example port completed!");
    println!("=====================================");

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Check MASP parameters first
    println!("📋 Check MASP parameters [{}]", get_timestamp());
    if !check_masp_params_exist()? {
        return Err(anyhow!(
            "MASP parameters not found. Please copy them to ./masp-params/"
        ));
    }
    println!("   ✅ MASP params verified");
    println!();

    // Setup ExtendedSpendingKey (exact same as JS example)
    println!("🔑 Setting up ExtendedSpendingKey from JS example");
    let xsk_str = "zsknam1qwkg258pqqqqpqypad9vytjs2j70eqak3fmuexhay8q3j560wjy0f6y5xe0zqlx5wkzzxnuk4y3pjyv0sexcrtevfldms9xy3mmq9erfmd7p5k85ddjs5nn7c3xg0e9mj3dkxt82sqjyuun7tvh8y3w0arup9mwwe4qugpsvlm995y49ej0gvs5ps7q2sdpru2vcjqdzzg2g6sx0cj6c789adffv2hz2l5xfjpvzlfqa55s3d4807chkjdq0vsllckyx4vnjd3ysmtg0mtuex";
    let xsk =
        ExtendedSpendingKey::from_str(xsk_str).context("Failed to parse ExtendedSpendingKey")?;
    println!("   ✅ Extended spending key parsed successfully");

    // Create PseudoExtendedKey and replace ask with fake one (same as JS)
    println!("🔧 Creating PseudoExtendedKey with fake spend authorization key");
    let masp_xsk = MaspExtendedSpendingKey::from(xsk);
    let mut pxk = PseudoExtendedKey::from(masp_xsk);

    // Critical: Replace spend authorizing key with fake one (same as JS)
    pxk.augment_spend_authorizing_key_unchecked(redjubjub::PrivateKey(
        masp_primitives::jubjub::Fr::default(),
    ));
    println!("   ✅ Spend authorization key replaced with Fr::default()");
    println!();

    // Setup RPC URL
    let rpc_url = "https://namada-rpc.emberstake.xyz".to_string();
    println!("🌐 Using RPC URL: {rpc_url}");
    println!();

    // Initialize SDK
    println!("📋 Initialize SDK [{}]", get_timestamp());
    println!("   RPC URL: {rpc_url}");

    // Create viewing key for wallet ID (derive from the real xsk for wallet ID)
    #[allow(deprecated)]
    let extended_full_viewing_key = masp_xsk.to_extended_full_viewing_key();
    let extended_viewing_key =
        namada_core::masp::ExtendedViewingKey::from(extended_full_viewing_key);
    let viewing_key_str = extended_viewing_key.to_string();
    println!("   🔑 Viewing key: {viewing_key_str}");

    // Create wallet ID from viewing key
    let wallet_id = create_wallet_id_from_viewing_key(&viewing_key_str);

    // Initialize SDK
    let sdk = initialize_sdk(rpc_url.clone(), Some(wallet_id)).await?;
    println!("   ✅ Namada SDK initialized successfully");

    // Generate disposable wrapper signing key
    println!(
        "📋 Generate disposable wrapper signing key [{}]",
        get_timestamp()
    );
    let (wrapper_secret_key, wrapper_public_key) = gen_disposable_signing_key_pair(&sdk).await;
    println!("   🔑 Generated disposable wrapper signing key");
    println!("   🔑 Public key: {wrapper_public_key}");
    println!();

    // Perform MASP sync
    println!("📋 Perform MASP sync [{}]", get_timestamp());
    println!("This mimics the exact flow from namada-interface PR #2235");
    println!();

    // Create viewing key for sync (derive from the PseudoExtendedKey)
    let extended_full_viewing_key = pxk.to_viewing_key();
    let extended_viewing_key =
        namada_core::masp::ExtendedViewingKey::from(extended_full_viewing_key);
    let viewing_key_str = extended_viewing_key.to_string();

    perform_masp_sync(&sdk, viewing_key_str).await?;
    println!("   ✅ MASP sync completed");
    println!();

    // Step 1: Build IBC unshielding transaction (unsecured)
    let (tx, signing_data, stored_build_params) =
        build_ibc_unshielding_tx(&sdk, pxk, rpc_url.clone(), wrapper_public_key).await?;

    // Step 2: Sign transaction - both MASP and wrapper (secured)
    let tx = sign_tx(
        tx,
        xsk,
        wrapper_secret_key,
        &signing_data,
        stored_build_params,
    )
    .await?;

    // Step 3: Broadcast transaction (unsecured)
    broadcast(tx, rpc_url).await?;

    Ok(())
}
