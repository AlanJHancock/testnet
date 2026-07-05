use serde_json::json;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use synergy_testnet::sts::{
    decode_sts_payload, encode_sts_payload, estimate_sts_gas, native_snrg_definition,
    validate_sts_object_id, CreateFungibleParams, FungibleControlFlags, FungiblePolicy,
    StsSignedPayload, StsState, StsTx, TokenClass, NATIVE_SNRG_PLACEHOLDER_ADDRESS,
    STS_TESTNET_CHAIN_ID, STS_TESTNET_NETWORK,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("synergy-sts failed closed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() || has_flag(&args, "--help") || has_flag(&args, "-h") {
        usage();
        return Ok(());
    }

    match args.first().map(String::as_str) {
        Some("version") | Some("--version") => {
            println!("synergy-sts {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("native-info") => print_native_info(&args[1..]),
        Some("decode") => decode_payload_command(&args[1..]),
        Some("estimate") => estimate_payload_command(&args[1..]),
        Some("token") => run_token_command(&args[1..]),
        Some("help") => {
            usage();
            Ok(())
        }
        Some(command) => Err(format!("unknown command '{command}'")),
        None => Ok(()),
    }
}

fn usage() {
    eprintln!(
        "synergy-sts

Build native Synergy Token System payloads for testnet. This tool does not
mutate chain state directly; wrap the emitted payload_hex in a signed Synergy
transaction and submit it through the normal transaction path.

Usage:
  synergy-sts native-info [--output json] [--out <path>]
  synergy-sts decode --payload-hex <hex> [--output json|payload-json] [--out <path>]
  synergy-sts decode --file <artifact.json-or-hex> [--output json|payload-json] [--out <path>]
  synergy-sts estimate --payload-hex <hex> [--gas-price-nwei <u64>]
  synergy-sts token create --network testnet --class b1|b2|b3 --name <name> --symbol <symbol> --decimals <0-9> --initial-supply <base_units> --from <creator> --creator-nonce <u64> [--created-at <u64>] [--max-supply <base_units>] [--metadata-uri <uri> --metadata-hash <sha3_256_hex>] [--metadata-file <path>] [--image-uri <uri> --image-hash <sha3_256_hex>] [--image-file <path>] [--no-mint-authority|--mint-authority <addr>] [--metadata-authority <addr>] [--can-freeze] [--can-pause] [--can-clawback] [--policy <template>] [--output json|payload-hex|payload-json] [--out <path>]
  synergy-sts token mint --network testnet --token <synb*> --to <owner> --amount <base_units> --from <authority> [--timestamp <u64>]
  synergy-sts token transfer --network testnet --token <synb*> --from <owner> --to <owner> --amount <base_units> [--timestamp <u64>]
  synergy-sts token burn --network testnet --token <synb*> --from <owner> --amount <base_units> [--timestamp <u64>]
  synergy-sts token set-image --network testnet --token <synb*> --image-uri <uri> --image-hash <sha3_256_hex> --from <creator> [--image-file <path>] [--timestamp <u64>]
  synergy-sts token freeze --network testnet --token <synb2*> --owner <owner> --from <authority> [--timestamp <u64>]
  synergy-sts token thaw --network testnet --token <synb2*> --owner <owner> --from <authority> [--timestamp <u64>]
  synergy-sts token pause --network testnet --token <synb2*> --from <authority> [--timestamp <u64>]
  synergy-sts token unpause --network testnet --token <synb2*> --from <authority> [--timestamp <u64>]
  synergy-sts token clawback --network testnet --token <synb2*> --source <owner> --to <owner> --amount <base_units> --from <authority> [--timestamp <u64>]
  synergy-sts token snapshot --network testnet --token <synb3*> --from <authority> [--timestamp <u64>]

Policy examples:
  --policy snapshot_v1
  --policy transfer_fee_v1:fee_bps=25,recipient=synw1...
  --policy vesting_v1:start_at=1700000000,cliff_at=1700000100,end_at=1700000200
  --policy max_wallet_v1:max_balance=1000000000
"
    );
}

fn run_token_command(args: &[String]) -> Result<(), String> {
    let Some(subcommand) = args.first().map(String::as_str) else {
        return Err("token command requires a subcommand".to_string());
    };
    let rest = &args[1..];
    require_testnet(rest)?;

    match subcommand {
        "create" => build_create_fungible(rest),
        "mint" => build_simple_amount_tx(rest, "mint"),
        "transfer" => build_simple_amount_tx(rest, "transfer"),
        "burn" => build_simple_amount_tx(rest, "burn"),
        "set-image" => build_set_image_tx(rest),
        "freeze" => build_account_control_tx(rest, true),
        "thaw" => build_account_control_tx(rest, false),
        "pause" => build_pause_tx(rest, true),
        "unpause" => build_pause_tx(rest, false),
        "clawback" => build_clawback_tx(rest),
        "snapshot" => build_snapshot_tx(rest),
        other => Err(format!("unknown token subcommand '{other}'")),
    }
}

fn print_native_info(args: &[String]) -> Result<(), String> {
    let native = native_snrg_definition();
    emit_output(
        args,
        json!({
            "network": STS_TESTNET_NETWORK,
            "chain_id": STS_TESTNET_CHAIN_ID,
            "symbol": native.symbol,
            "name": native.name,
            "decimals": native.decimals,
            "native": native.native,
            "gas_asset": native.gas_asset,
            "token_address": native.token_address,
            "compatibility_placeholder_address": NATIVE_SNRG_PLACEHOLDER_ADDRESS,
        }),
    )
}

fn decode_payload_command(args: &[String]) -> Result<(), String> {
    let payload_hex = payload_hex_from_args(args)?;
    let payload = decode_payload_hex(&payload_hex)?;
    emit_output(
        args,
        payload_report(payload, payload_hex, None, None, None)?,
    )
}

fn estimate_payload_command(args: &[String]) -> Result<(), String> {
    let gas_price_nwei = optional_u64_arg(args, "--gas-price-nwei")?.unwrap_or(40);
    let payload_hex = payload_hex_from_args(args)?;
    let payload = decode_payload_hex(&payload_hex)?;
    let gas = estimate_sts_gas(&payload.tx);
    let fee_nwei = (gas as u128)
        .checked_mul(gas_price_nwei as u128)
        .ok_or_else(|| "estimated fee overflow".to_string())?;
    emit_output(
        args,
        json!({
            "network": payload.network,
            "chain_id": payload.chain_id,
            "estimated_gas": gas,
            "gas_price_nwei": gas_price_nwei,
            "estimated_fee_nwei": fee_nwei.to_string(),
            "payload": payload,
        }),
    )
}

fn build_create_fungible(args: &[String]) -> Result<(), String> {
    let class = parse_token_class(&required_arg(args, "--class")?)?;
    if !class.is_fungible() {
        return Err("token create currently supports fungible classes b1, b2, and b3".to_string());
    }

    let metadata_uri = optional_arg(args, "--metadata-uri");
    let metadata_file = optional_arg(args, "--metadata-file");
    let metadata_file_hash = metadata_file
        .as_deref()
        .map(hash_file_sha3_256)
        .transpose()?;
    let metadata_hash = match (
        optional_arg(args, "--metadata-hash"),
        metadata_file_hash.as_ref(),
    ) {
        (Some(explicit), Some(file_hash)) if explicit.as_str() != file_hash.as_str() => {
            return Err(format!(
                "--metadata-hash does not match SHA3-256(metadata-file): expected {file_hash}"
            ));
        }
        (Some(explicit), _) => Some(explicit),
        (None, Some(file_hash)) => Some(file_hash.clone()),
        (None, None) => None,
    };
    if metadata_uri.is_some() && metadata_hash.is_none() {
        return Err("--metadata-hash is required when --metadata-uri is provided".to_string());
    }

    let image_uri = optional_arg(args, "--image-uri");
    let image_file = optional_arg(args, "--image-file");
    let image_file_hash = image_file.as_deref().map(hash_file_sha3_256).transpose()?;
    let image_hash = match (optional_arg(args, "--image-hash"), image_file_hash.as_ref()) {
        (Some(explicit), Some(file_hash)) if explicit.as_str() != file_hash.as_str() => {
            return Err(format!(
                "--image-hash does not match SHA3-256(image-file): expected {file_hash}"
            ));
        }
        (Some(explicit), _) => Some(explicit),
        (None, Some(file_hash)) => Some(file_hash.clone()),
        (None, None) => None,
    };
    if image_uri.is_some() && image_hash.is_none() {
        return Err("--image-hash is required when --image-uri is provided".to_string());
    }
    if image_uri.is_none() && image_hash.is_some() {
        return Err(
            "--image-uri is required when --image-hash or --image-file is provided".to_string(),
        );
    }

    let creator = required_arg(args, "--from")?;
    let created_at = optional_u64_arg(args, "--created-at")?.unwrap_or(current_timestamp()?);
    let creator_nonce = required_u64_arg(args, "--creator-nonce")?;
    let mint_authority = if has_flag(args, "--no-mint-authority") {
        if optional_arg(args, "--mint-authority").is_some() {
            return Err("--no-mint-authority cannot be combined with --mint-authority".to_string());
        }
        None
    } else {
        optional_arg(args, "--mint-authority").or_else(|| Some(creator.clone()))
    };
    let params = CreateFungibleParams {
        class,
        creator: creator.clone(),
        creator_nonce,
        name: required_arg(args, "--name")?,
        symbol: required_arg(args, "--symbol")?,
        decimals: required_u8_arg(args, "--decimals")?,
        initial_supply: required_u128_arg(args, "--initial-supply")?,
        max_supply: optional_u128_arg(args, "--max-supply")?,
        mint_authority,
        metadata_authority: optional_arg(args, "--metadata-authority")
            .or_else(|| has_flag(args, "--metadata-mutable").then(|| creator.clone())),
        metadata_uri,
        metadata_hash: metadata_hash.clone(),
        metadata_mutable: has_flag(args, "--metadata-mutable"),
        image_uri: image_uri.clone(),
        image_hash: image_hash.clone(),
        flags: FungibleControlFlags {
            can_freeze: has_flag(args, "--can-freeze"),
            can_pause: has_flag(args, "--can-pause"),
            can_clawback: has_flag(args, "--can-clawback"),
            can_denylist: has_flag(args, "--can-denylist"),
            can_allowlist: has_flag(args, "--can-allowlist"),
            can_update_metadata: has_flag(args, "--can-update-metadata"),
            requires_transfer_approval: has_flag(args, "--requires-transfer-approval"),
        },
        policies: parse_policies(args)?,
        created_at,
    };

    let mut preview = StsState::new();
    let token_id = preview
        .create_fungible(params.clone())
        .map_err(|error| format!("create payload rejected by STS policy: {error}"))?;
    let token_address = preview
        .token_registry
        .get(&token_id)
        .map(|definition| definition.token_address.clone())
        .ok_or_else(|| "preview token registry did not contain created token".to_string())?;

    let tx = StsTx::CreateFungible(params);
    print_payload(
        args,
        &creator,
        StsSignedPayload::new(tx),
        Some(token_id),
        Some(token_address),
        Some(json!({
            "metadata_file": metadata_file,
            "metadata_file_sha3_256": metadata_file_hash,
            "image_file": image_file,
            "image_file_sha3_256": image_file_hash,
            "image_uri": image_uri,
            "image_hash": image_hash,
        })),
    )
}

fn build_set_image_tx(args: &[String]) -> Result<(), String> {
    let sender = required_arg(args, "--from")?;
    let token_id = required_arg(args, "--token")?;
    validate_fungible_token_id(&token_id)?;
    let image_uri = required_arg(args, "--image-uri")?;
    let image_file = optional_arg(args, "--image-file");
    let image_file_hash = image_file.as_deref().map(hash_file_sha3_256).transpose()?;
    let image_hash = match (
        required_arg(args, "--image-hash")?,
        image_file_hash.as_ref(),
    ) {
        (explicit, Some(file_hash)) if explicit.as_str() != file_hash.as_str() => {
            return Err(format!(
                "--image-hash does not match SHA3-256(image-file): expected {file_hash}"
            ));
        }
        (explicit, _) => explicit,
    };
    validate_image_uri_hash(&image_uri, &image_hash)?;
    let timestamp = optional_u64_arg(args, "--timestamp")?.unwrap_or(current_timestamp()?);
    print_payload(
        args,
        &sender,
        StsSignedPayload::new(StsTx::SetFungibleImage {
            token_id,
            image_uri: image_uri.clone(),
            image_hash: image_hash.clone(),
            timestamp,
        }),
        None,
        None,
        Some(json!({
            "image_file": image_file,
            "image_file_sha3_256": image_file_hash,
            "image_uri": image_uri,
            "image_hash": image_hash,
        })),
    )
}

fn build_simple_amount_tx(args: &[String], op: &str) -> Result<(), String> {
    let token_id = required_arg(args, "--token")?;
    validate_fungible_token_id(&token_id)?;
    let amount = required_u128_arg(args, "--amount")?;
    let timestamp = optional_u64_arg(args, "--timestamp")?.unwrap_or(current_timestamp()?);

    let (sender, tx) = match op {
        "mint" => {
            let sender = required_arg(args, "--from")?;
            let to = required_arg(args, "--to")?;
            (
                sender,
                StsTx::MintFungible {
                    token_id,
                    to,
                    amount,
                    timestamp,
                },
            )
        }
        "transfer" => {
            let from = required_arg(args, "--from")?;
            let to = required_arg(args, "--to")?;
            (
                from.clone(),
                StsTx::TransferFungible {
                    token_id,
                    from,
                    to,
                    amount,
                    timestamp,
                },
            )
        }
        "burn" => {
            let from = required_arg(args, "--from")?;
            (
                from.clone(),
                StsTx::BurnFungible {
                    token_id,
                    from,
                    amount,
                    timestamp,
                },
            )
        }
        _ => return Err(format!("unsupported simple amount op '{op}'")),
    };
    print_payload(args, &sender, StsSignedPayload::new(tx), None, None, None)
}

fn build_account_control_tx(args: &[String], frozen: bool) -> Result<(), String> {
    let sender = required_arg(args, "--from")?;
    let token_id = required_arg(args, "--token")?;
    validate_sts_object_id(TokenClass::B2ManagedFungible, &token_id)
        .map_err(|_| "--token must be a synb2 managed fungible token ID".to_string())?;
    let owner = required_arg(args, "--owner")?;
    let timestamp = optional_u64_arg(args, "--timestamp")?.unwrap_or(current_timestamp()?);
    let tx = if frozen {
        StsTx::FreezeFungibleAccount {
            token_id,
            owner,
            timestamp,
        }
    } else {
        StsTx::ThawFungibleAccount {
            token_id,
            owner,
            timestamp,
        }
    };
    print_payload(args, &sender, StsSignedPayload::new(tx), None, None, None)
}

fn build_pause_tx(args: &[String], paused: bool) -> Result<(), String> {
    let sender = required_arg(args, "--from")?;
    let token_id = required_arg(args, "--token")?;
    validate_sts_object_id(TokenClass::B2ManagedFungible, &token_id)
        .map_err(|_| "--token must be a synb2 managed fungible token ID".to_string())?;
    let timestamp = optional_u64_arg(args, "--timestamp")?.unwrap_or(current_timestamp()?);
    let tx = if paused {
        StsTx::PauseFungible {
            token_id,
            timestamp,
        }
    } else {
        StsTx::UnpauseFungible {
            token_id,
            timestamp,
        }
    };
    print_payload(args, &sender, StsSignedPayload::new(tx), None, None, None)
}

fn build_clawback_tx(args: &[String]) -> Result<(), String> {
    let sender = required_arg(args, "--from")?;
    let token_id = required_arg(args, "--token")?;
    validate_sts_object_id(TokenClass::B2ManagedFungible, &token_id)
        .map_err(|_| "--token must be a synb2 managed fungible token ID".to_string())?;
    let from = required_arg(args, "--source")?;
    let to = required_arg(args, "--to")?;
    let amount = required_u128_arg(args, "--amount")?;
    let timestamp = optional_u64_arg(args, "--timestamp")?.unwrap_or(current_timestamp()?);
    print_payload(
        args,
        &sender,
        StsSignedPayload::new(StsTx::ClawbackFungible {
            token_id,
            from,
            to,
            amount,
            timestamp,
        }),
        None,
        None,
        None,
    )
}

fn build_snapshot_tx(args: &[String]) -> Result<(), String> {
    let sender = required_arg(args, "--from")?;
    let token_id = required_arg(args, "--token")?;
    validate_sts_object_id(TokenClass::B3PolicyFungible, &token_id)
        .map_err(|_| "--token must be a synb3 policy fungible token ID".to_string())?;
    let timestamp = optional_u64_arg(args, "--timestamp")?.unwrap_or(current_timestamp()?);
    print_payload(
        args,
        &sender,
        StsSignedPayload::new(StsTx::CreateFungibleSnapshot {
            token_id,
            timestamp,
        }),
        None,
        None,
        None,
    )
}

fn print_payload(
    args: &[String],
    sender: &str,
    payload: StsSignedPayload,
    expected_token_id: Option<String>,
    expected_token_address: Option<String>,
    metadata_artifact: Option<serde_json::Value>,
) -> Result<(), String> {
    payload
        .require_testnet()
        .map_err(|error| format!("invalid STS payload network: {error}"))?;
    let payload_hex = hex::encode(
        encode_sts_payload(&payload)
            .map_err(|error| format!("payload encoding failed: {error}"))?,
    );
    let gas = estimate_sts_gas(&payload.tx);
    let gas_price_nwei = optional_u64_arg(args, "--gas-price-nwei")?.unwrap_or(40);
    let estimated_fee_nwei = (gas as u128)
        .checked_mul(gas_price_nwei as u128)
        .ok_or_else(|| "estimated fee overflow".to_string())?;
    emit_output(
        args,
        json!({
            "network": payload.network,
            "chain_id": payload.chain_id,
            "sender": sender,
            "estimated_gas": gas,
            "gas_price_nwei": gas_price_nwei,
            "estimated_fee_nwei": estimated_fee_nwei.to_string(),
            "expected_token_id": expected_token_id,
            "expected_token_address": expected_token_address,
            "native_snrg_token_address": serde_json::Value::Null,
            "native_snrg_compatibility_placeholder_address": NATIVE_SNRG_PLACEHOLDER_ADDRESS,
            "metadata": metadata_artifact,
            "payload_hex": payload_hex,
            "payload": payload,
        }),
    )
}

fn payload_report(
    payload: StsSignedPayload,
    payload_hex: String,
    expected_token_id: Option<String>,
    expected_token_address: Option<String>,
    metadata_artifact: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    payload
        .require_testnet()
        .map_err(|error| format!("invalid STS payload network: {error}"))?;
    let gas = estimate_sts_gas(&payload.tx);
    Ok(json!({
        "network": payload.network,
        "chain_id": payload.chain_id,
        "estimated_gas": gas,
        "expected_token_id": expected_token_id,
        "expected_token_address": expected_token_address,
        "native_snrg_token_address": serde_json::Value::Null,
        "native_snrg_compatibility_placeholder_address": NATIVE_SNRG_PLACEHOLDER_ADDRESS,
        "metadata": metadata_artifact,
        "payload_hex": payload_hex,
        "payload": payload,
    }))
}

fn decode_payload_hex(payload_hex: &str) -> Result<StsSignedPayload, String> {
    let normalized = payload_hex.trim();
    if normalized.starts_with("0x") {
        return Err("payload hex must be lowercase hex without 0x".to_string());
    }
    if !normalized
        .chars()
        .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
    {
        return Err("payload hex must be lowercase hex".to_string());
    }
    let bytes = hex::decode(normalized).map_err(|error| format!("invalid payload hex: {error}"))?;
    decode_sts_payload(&bytes)
        .map_err(|error| format!("invalid STS payload: {error}"))?
        .ok_or_else(|| "payload bytes do not contain the STS prefix".to_string())
}

fn payload_hex_from_args(args: &[String]) -> Result<String, String> {
    if let Some(payload_hex) = optional_arg(args, "--payload-hex") {
        return Ok(payload_hex);
    }
    let file = required_arg(args, "--file")?;
    let contents =
        fs::read_to_string(&file).map_err(|error| format!("failed to read {file}: {error}"))?;
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&contents) {
        if let Some(payload_hex) = value.get("payload_hex").and_then(|value| value.as_str()) {
            return Ok(payload_hex.to_string());
        }
        return Err(format!("{file} is JSON but does not contain payload_hex"));
    }
    Ok(contents.trim().to_string())
}

fn validate_fungible_token_id(token_id: &str) -> Result<TokenClass, String> {
    let class = fungible_class_from_token_id(token_id)
        .ok_or_else(|| "--token must start with synb1, synb2, or synb3".to_string())?;
    validate_sts_object_id(class, token_id)
        .map_err(|_| format!("--token is not a valid {} object ID", class.prefix()))?;
    Ok(class)
}

fn fungible_class_from_token_id(token_id: &str) -> Option<TokenClass> {
    if token_id.starts_with(TokenClass::B1BasicFungible.prefix()) {
        Some(TokenClass::B1BasicFungible)
    } else if token_id.starts_with(TokenClass::B2ManagedFungible.prefix()) {
        Some(TokenClass::B2ManagedFungible)
    } else if token_id.starts_with(TokenClass::B3PolicyFungible.prefix()) {
        Some(TokenClass::B3PolicyFungible)
    } else {
        None
    }
}

fn hash_file_sha3_256(path: &str) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| format!("failed to read file {path}: {error}"))?;
    Ok(sha3_256_hex(&bytes))
}

fn validate_image_uri_hash(image_uri: &str, image_hash: &str) -> Result<(), String> {
    let allowed = image_uri.starts_with("ipfs://")
        || image_uri.starts_with("ar://")
        || image_uri.starts_with("https://");
    if !allowed
        || image_uri.len() > 512
        || image_uri
            .chars()
            .any(|ch| ch.is_ascii_control() || ch.is_ascii_whitespace() || ch == '\\')
        || image_uri.to_ascii_lowercase().contains(".svg")
    {
        return Err("image URI must be ipfs://, ar://, or https://, must not contain whitespace, and must not reference SVG".to_string());
    }
    if image_hash.len() != 64
        || image_hash.starts_with("0x")
        || !image_hash
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
    {
        return Err(
            "image hash must be 64 lowercase SHA3-256 hex characters without 0x".to_string(),
        );
    }
    Ok(())
}

fn emit_output(args: &[String], value: serde_json::Value) -> Result<(), String> {
    let output = match optional_arg(args, "--output")
        .unwrap_or_else(|| "json".to_string())
        .as_str()
    {
        "json" => serde_json::to_string_pretty(&value).map_err(|error| error.to_string())?,
        "compact-json" => serde_json::to_string(&value).map_err(|error| error.to_string())?,
        "payload-hex" => value
            .get("payload_hex")
            .and_then(|value| value.as_str())
            .ok_or_else(|| "--output payload-hex requires a payload artifact".to_string())?
            .to_string(),
        "payload-json" => serde_json::to_string_pretty(
            value
                .get("payload")
                .ok_or_else(|| "--output payload-json requires a payload artifact".to_string())?,
        )
        .map_err(|error| error.to_string())?,
        other => {
            return Err(format!(
                "unsupported --output '{other}'; use json, compact-json, payload-hex, or payload-json"
            ));
        }
    };

    if let Some(path) = optional_arg(args, "--out") {
        fs::write(&path, output.as_bytes())
            .map_err(|error| format!("failed to write {path}: {error}"))?;
    }
    println!("{output}");
    Ok(())
}

fn parse_token_class(value: &str) -> Result<TokenClass, String> {
    TokenClass::from_wire(value).map_err(|_| format!("invalid STS token class '{value}'"))
}

fn parse_policies(args: &[String]) -> Result<Vec<FungiblePolicy>, String> {
    arg_values(args, "--policy")
        .into_iter()
        .map(|value| parse_policy(&value))
        .collect()
}

fn parse_policy(value: &str) -> Result<FungiblePolicy, String> {
    let (template, raw_fields) = value.split_once(':').unwrap_or((value, ""));
    let fields = parse_policy_fields(raw_fields);
    match template {
        "snapshot_v1" => Ok(FungiblePolicy::SnapshotV1),
        "transfer_fee_v1" => Ok(FungiblePolicy::TransferFeeV1 {
            fee_bps: required_policy_field(&fields, "fee_bps")?
                .parse::<u16>()
                .map_err(|_| "transfer_fee_v1 fee_bps must be u16".to_string())?,
            recipient: required_policy_field(&fields, "recipient")?.to_string(),
        }),
        "vesting_v1" => Ok(FungiblePolicy::VestingV1 {
            start_at: required_policy_field(&fields, "start_at")?
                .parse::<u64>()
                .map_err(|_| "vesting_v1 start_at must be u64".to_string())?,
            cliff_at: required_policy_field(&fields, "cliff_at")?
                .parse::<u64>()
                .map_err(|_| "vesting_v1 cliff_at must be u64".to_string())?,
            end_at: required_policy_field(&fields, "end_at")?
                .parse::<u64>()
                .map_err(|_| "vesting_v1 end_at must be u64".to_string())?,
        }),
        "max_wallet_v1" => Ok(FungiblePolicy::MaxWalletV1 {
            max_balance: required_policy_field(&fields, "max_balance")?
                .parse::<u128>()
                .map_err(|_| "max_wallet_v1 max_balance must be u128 base units".to_string())?,
        }),
        other => Err(format!("unsupported STS policy template '{other}'")),
    }
}

fn parse_policy_fields(raw: &str) -> Vec<(&str, &str)> {
    raw.split(',')
        .filter_map(|part| part.split_once('='))
        .collect::<Vec<_>>()
}

fn required_policy_field<'a>(fields: &'a [(&str, &str)], key: &str) -> Result<&'a str, String> {
    fields
        .iter()
        .find_map(|(field_key, value)| (*field_key == key).then_some(*value))
        .ok_or_else(|| format!("policy field '{key}' is required"))
}

fn require_testnet(args: &[String]) -> Result<(), String> {
    let network =
        optional_arg(args, "--network").unwrap_or_else(|| STS_TESTNET_NETWORK.to_string());
    if network != STS_TESTNET_NETWORK {
        return Err(format!(
            "synergy-sts is testnet-only in this implementation; got network '{network}'"
        ));
    }
    Ok(())
}

fn optional_arg(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find_map(|window| (window[0] == name).then(|| window[1].clone()))
}

fn required_arg(args: &[String], name: &str) -> Result<String, String> {
    optional_arg(args, name).ok_or_else(|| format!("{name} is required"))
}

fn arg_values(args: &[String], name: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut index = 0usize;
    while index < args.len() {
        if args[index] == name {
            if let Some(value) = args.get(index + 1) {
                values.push(value.clone());
                index += 2;
                continue;
            }
        }
        index += 1;
    }
    values
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|arg| arg == name)
}

fn required_u8_arg(args: &[String], name: &str) -> Result<u8, String> {
    required_arg(args, name)?
        .parse::<u8>()
        .map_err(|_| format!("{name} must be u8"))
}

fn required_u64_arg(args: &[String], name: &str) -> Result<u64, String> {
    required_arg(args, name)?
        .parse::<u64>()
        .map_err(|_| format!("{name} must be u64"))
}

fn optional_u64_arg(args: &[String], name: &str) -> Result<Option<u64>, String> {
    optional_arg(args, name)
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| format!("{name} must be u64"))
        })
        .transpose()
}

fn required_u128_arg(args: &[String], name: &str) -> Result<u128, String> {
    required_arg(args, name)?
        .parse::<u128>()
        .map_err(|_| format!("{name} must be u128 base units"))
}

fn optional_u128_arg(args: &[String], name: &str) -> Result<Option<u128>, String> {
    optional_arg(args, name)
        .map(|value| {
            value
                .parse::<u128>()
                .map_err(|_| format!("{name} must be u128 base units"))
        })
        .transpose()
}

fn current_timestamp() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before Unix epoch".to_string())
        .map(|duration| duration.as_secs())
}

fn sha3_256_hex(bytes: &[u8]) -> String {
    use sha3::{Digest, Sha3_256};
    let hash: [u8; 32] = Sha3_256::digest(bytes).into();
    hex::encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_policy_templates() {
        assert!(matches!(
            parse_policy("snapshot_v1").unwrap(),
            FungiblePolicy::SnapshotV1
        ));
        assert!(matches!(
            parse_policy("transfer_fee_v1:fee_bps=25,recipient=synw1abc").unwrap(),
            FungiblePolicy::TransferFeeV1 { .. }
        ));
        assert!(matches!(
            parse_policy("max_wallet_v1:max_balance=1000").unwrap(),
            FungiblePolicy::MaxWalletV1 { max_balance: 1000 }
        ));
        assert!(parse_policy("unsupported_v1").is_err());
    }

    #[test]
    fn rejects_non_testnet_network() {
        let args = vec!["--network".to_string(), "mainnet".to_string()];
        assert!(require_testnet(&args).is_err());
    }

    #[test]
    fn decodes_lowercase_sts_payload_hex_and_rejects_0x() {
        let payload = StsSignedPayload::new(StsTx::TransferFungible {
            token_id: "synb11w7523v07vcc4n28knfnvyt6lq8649mey8p5ywd".to_string(),
            from: "synw1from000000000000000000000000000000".to_string(),
            to: "synw1to00000000000000000000000000000000".to_string(),
            amount: 1,
            timestamp: 1_700_000_000,
        });
        let hex_payload = hex::encode(encode_sts_payload(&payload).unwrap());
        assert_eq!(decode_payload_hex(&hex_payload).unwrap(), payload);
        assert!(decode_payload_hex(&format!("0x{hex_payload}")).is_err());
    }

    #[test]
    fn fungible_token_prefix_validation_is_class_aware() {
        assert!(validate_fungible_token_id("synb11w7523v07vcc4n28knfnvyt6lq8649mey8p5ywd").is_ok());
        assert!(validate_sts_object_id(
            TokenClass::B2ManagedFungible,
            "synb11w7523v07vcc4n28knfnvyt6lq8649mey8p5ywd"
        )
        .is_err());
    }
}
