use anyhow::{bail, Context, Result};
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint};
use bitcoin::key::XOnlyPublicKey;
use bitcoin::{Amount, Txid};
use psbt::roles::signer::extract_eligible_input_pubkey;
use psbt::Psbt as SilentPaymentPsbt;
use secp256k1::{PublicKey, Secp256k1};
use silentpayments::receiving::{Label, Receiver};
use silentpayments::utils::receiving::PublicTweakData;
use silentpayments::utils::OutPoint as SpOutPoint;
use silentpayments::{Network, SpVersion, TransactionInputs, TransactionSharedSecret};
use std::fs;
use std::path::{Path, PathBuf};

use crate::demo::workflow::{self, KeySetup};
use crate::musig2_psbt::get_output_sp_info;
use crate::recipients::{address_amounts, load_recipients, recipient_keys};

const FIXTURE_PREV_TXID_HEX: &str =
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

const BIP48_ACCOUNT_PATH: [u32; 4] = [0x80000030, 0x80000001, 0x80000000, 0x80000003];

struct Cosigner {
    xfp: [u8; 4],
    xpub_str: &'static str,
}

static COSIGNERS_TEST: [Cosigner; 3] = [
    Cosigner {
        xfp: [0x0f, 0x05, 0x69, 0x43],
        xpub_str: "tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez",
    },
    Cosigner {
        xfp: [0x6b, 0xa6, 0xcf, 0xd0],
        xpub_str: "tpubDFcrvj5n7gyazzxdg9k6uvzQsoQWow1xbksr7EvKPRBgUbwCdqu2qxyTJjYFNJ7MQLfdXSJV4n8xPZGtrvwQtEbktinC4EP3k8JN2hcBtz4",
    },
    Cosigner {
        xfp: [0x74, 0x7b, 0x69, 0x8e],
        xpub_str: "tpubDExj5FnaUnPAnoAge8edwn7qr8VdquTossNwPPPZVdGH3AZ3et8vVNnJXagqq18d4QWYoja9GeHfpVGZQjQAHozrSHK1HZtnF4XCE1RwE24",
    },
];

#[derive(Debug, Clone)]
pub struct BuildPayrollConfig {
    pub recipients_path: PathBuf,
    pub out_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct PayrollOutput {
    pub output_index: usize,
    pub amount: Amount,
    pub script_pubkey_hex: String,
    pub address: String,
}

#[derive(Debug, Clone)]
pub struct BuildPayrollResult {
    pub round1_psbt_path: PathBuf,
    pub cosigner_contrib_psbt_path: PathBuf,
    pub descriptor_path: PathBuf,
    pub descriptor: String,
    pub recipient_count: usize,
    pub outputs: Vec<PayrollOutput>,
}

#[derive(Debug, Clone)]
pub struct RecipientScanResult {
    pub recipient_index: usize,
    pub label: Option<String>,
    pub expected_amount_sat: u64,
    pub detections: Vec<DetectedOutput>,
}

#[derive(Debug, Clone)]
pub struct DetectedOutput {
    pub output_index: usize,
    pub amount_sat: u64,
    pub xonly_hex: String,
    pub amount_matches: bool,
}

#[derive(Debug, Clone)]
pub struct ScanRecipientsResult {
    pub candidate_outputs: usize,
    pub recipient_results: Vec<RecipientScanResult>,
}

pub fn build_payroll(config: BuildPayrollConfig) -> Result<BuildPayrollResult> {
    fs::create_dir_all(&config.out_dir)
        .with_context(|| format!("failed to create {}", config.out_dir.display()))?;

    let secp = Secp256k1::new();
    let keys = workflow::setup_keys(&secp, workflow::DEMO_SP_INDEX)?;
    let recipients = load_recipients(&config.recipients_path)?;
    let recipient_pairs = address_amounts(&recipients);

    let mut psbt = workflow::construct_psbt(&keys, &recipient_pairs)?;
    psbt.inputs[0].previous_txid = FIXTURE_PREV_TXID_HEX.parse::<Txid>().expect("static txid");

    add_payroll_tap_derivations(&mut psbt, &keys)?;

    let round1_psbt_path = config.out_dir.join("musig2-sp-round1-in.psbt");
    fs::write(&round1_psbt_path, psbt.serialize())?;

    let scan_keys: Vec<_> = recipient_pairs
        .iter()
        .map(|(addr, _)| addr.get_scan_key())
        .collect();
    add_party_contribution(&secp, &mut psbt, &keys, "Bob", &scan_keys)?;
    add_party_contribution(&secp, &mut psbt, &keys, "Charlie", &scan_keys)?;

    let cosigner_contrib_psbt_path = config.out_dir.join("musig2-sp-cosigner-contrib.psbt");
    fs::write(&cosigner_contrib_psbt_path, psbt.serialize())?;

    add_party_contribution(&secp, &mut psbt, &keys, "Alice", &scan_keys)?;

    let descriptor = build_descriptor();
    let descriptor_path = config.out_dir.join("desc-musig-sp-demo.txt");
    fs::write(&descriptor_path, &descriptor)?;

    workflow::derive_sp_output(&secp, &mut psbt)?;
    let outputs = payroll_outputs(&psbt, &recipient_pairs)?;

    Ok(BuildPayrollResult {
        round1_psbt_path,
        cosigner_contrib_psbt_path,
        descriptor_path,
        descriptor,
        recipient_count: recipients.len(),
        outputs,
    })
}

pub fn scan_recipients(
    psbt_path: impl AsRef<Path>,
    recipients_path: impl AsRef<Path>,
) -> Result<ScanRecipientsResult> {
    let recipients = load_recipients(recipients_path)?;
    let psbt_path = psbt_path.as_ref();
    let secp = Secp256k1::new();
    let psbt_bytes = fs::read(psbt_path)
        .with_context(|| format!("failed to read PSBT {}", psbt_path.display()))?;
    let psbt = SilentPaymentPsbt::deserialize(&psbt_bytes).context("failed to parse PSBT")?;

    let mut tx_inputs = TransactionInputs::with_capacity(psbt.inputs.len());
    let mut eligible_count = 0usize;
    for input in &psbt.inputs {
        let outpoint = SpOutPoint::from_txid_and_vout(
            input.previous_txid.to_string(),
            input.spent_output_index,
        )
        .map_err(|e| anyhow::anyhow!("outpoint: {e}"))?;
        let script_pubkey = input
            .witness_utxo
            .as_ref()
            .map(|u| u.script_pubkey.to_bytes())
            .unwrap_or_default();
        let pubkey = extract_eligible_input_pubkey(input)
            .map_err(|e| anyhow::anyhow!("input pubkey: {e:?}"))?;
        if pubkey.is_some() {
            eligible_count += 1;
        }
        tx_inputs.push(outpoint, script_pubkey, pubkey);
    }
    if eligible_count == 0 {
        bail!("no eligible inputs to derive tweak data");
    }

    let tweak_data = PublicTweakData::new(&secp, &tx_inputs)
        .map_err(|e| anyhow::anyhow!("calculate tweak data: {e}"))?;

    let mut candidates = Vec::new();
    for (idx, output) in psbt.outputs.iter().enumerate() {
        if output.script_pubkey.is_p2tr() {
            let xonly =
                secp256k1::XOnlyPublicKey::from_slice(&output.script_pubkey.as_bytes()[2..34])
                    .map_err(|e| anyhow::anyhow!("output {idx} x-only: {e}"))?;
            candidates.push((idx, xonly, output.amount.to_sat()));
        }
    }
    let candidate_xonly: Vec<_> = candidates.iter().map(|(_, x, _)| *x).collect();

    let mut recipient_results = Vec::new();
    for (idx, recipient) in recipients.iter().enumerate() {
        let seed = recipient.seed.as_ref().ok_or_else(|| {
            anyhow::anyhow!("recipient[{idx}] has no seed_hex; cannot receiver-scan")
        })?;
        let (scan_sk, spend_sk) = recipient_keys(seed);
        let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
        let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);
        let receiver = Receiver::new(
            SpVersion::ZERO,
            scan_pk,
            spend_pk,
            Label::new(scan_sk, 0),
            Network::Mainnet,
        )
        .map_err(|e| anyhow::anyhow!("Receiver::new: {e}"))?;

        let shared_secret =
            TransactionSharedSecret::new_from_public_tweak_data(&secp, &tweak_data, &scan_sk)
                .map_err(|e| anyhow::anyhow!("shared secret: {e}"))?;
        let found = receiver
            .scan_transaction(&shared_secret, &candidate_xonly)
            .map_err(|e| anyhow::anyhow!("scan_transaction: {e}"))?;

        let mut detections = Vec::new();
        for xonly in found.values().flat_map(|m| m.keys().copied()) {
            if let Some((output_index, _, amount_sat)) = candidates
                .iter()
                .find(|(_, candidate, _)| *candidate == xonly)
            {
                detections.push(DetectedOutput {
                    output_index: *output_index,
                    amount_sat: *amount_sat,
                    xonly_hex: hex::encode(xonly.serialize()),
                    amount_matches: *amount_sat == recipient.amount.to_sat(),
                });
            }
        }

        recipient_results.push(RecipientScanResult {
            recipient_index: idx,
            label: recipient.label.clone(),
            expected_amount_sat: recipient.amount.to_sat(),
            detections,
        });
    }

    if recipient_results.iter().any(|result| {
        result.detections.is_empty() || result.detections.iter().any(|d| !d.amount_matches)
    }) {
        bail!("one or more recipients could not detect the expected output");
    }

    Ok(ScanRecipientsResult {
        candidate_outputs: candidate_xonly.len(),
        recipient_results,
    })
}

fn add_payroll_tap_derivations(psbt: &mut SilentPaymentPsbt, keys: &KeySetup) -> Result<()> {
    let change_idx = psbt
        .outputs
        .iter()
        .position(|output| output.sp_v0_info.is_none())
        .ok_or_else(|| anyhow::anyhow!("no change output present"))?;

    for (participant_pk, cosigner) in [keys.alice_pk, keys.bob_pk, keys.charlie_pk]
        .iter()
        .zip(COSIGNERS_TEST.iter())
    {
        let (xonly, _) = participant_pk.x_only_public_key();
        add_tap_derivation(psbt, change_idx, &xonly, cosigner.xfp, &BIP48_ACCOUNT_PATH);
    }
    Ok(())
}

fn add_tap_derivation(
    psbt: &mut SilentPaymentPsbt,
    change_idx: usize,
    xonly: &XOnlyPublicKey,
    xfp: [u8; 4],
    path: &[u32],
) {
    let fp = Fingerprint::from(xfp);
    let dpath: DerivationPath = path.iter().map(|&n| ChildNumber::from(n)).collect();
    psbt.inputs[0]
        .tap_key_origins
        .insert(*xonly, (Vec::new(), (fp, dpath.clone())));
    psbt.outputs[change_idx]
        .tap_key_origins
        .insert(*xonly, (Vec::new(), (fp, dpath)));
}

fn add_party_contribution(
    secp: &Secp256k1<secp256k1::All>,
    psbt: &mut SilentPaymentPsbt,
    keys: &KeySetup,
    party: &str,
    scan_keys: &[PublicKey],
) -> Result<()> {
    let (party_sk, party_pk) = match party {
        "Alice" => (&keys.alice_sk, &keys.alice_pk),
        "Bob" => (&keys.bob_sk, &keys.bob_pk),
        "Charlie" => (&keys.charlie_sk, &keys.charlie_pk),
        _ => bail!("unknown party {party}"),
    };

    let first_scan_key = scan_keys
        .first()
        .ok_or_else(|| anyhow::anyhow!("payroll requires at least one recipient"))?;
    workflow::contribute(
        secp,
        psbt,
        party,
        party_sk,
        party_pk,
        first_scan_key,
        &keys.agg_pk,
        &keys.key_agg_ctx,
        test_nonce_seed(party),
    )?;
    for scan_key in &scan_keys[1..] {
        workflow::add_ecdh_share(secp, psbt, party, party_sk, party_pk, scan_key)?;
    }
    Ok(())
}

fn test_nonce_seed(party: &str) -> [u8; 32] {
    let mut seed = [0u8; 32];
    let bytes = party.as_bytes();
    let len = bytes.len().min(32);
    seed[..len].copy_from_slice(&bytes[..len]);
    seed
}

fn build_descriptor() -> String {
    let parts: Vec<String> = COSIGNERS_TEST
        .iter()
        .map(|cosigner| {
            let xfp_hex = hex::encode(cosigner.xfp);
            format!("[{}/48h/1h/0h/3h]{}", xfp_hex, cosigner.xpub_str)
        })
        .collect();
    format!("tr(musig({})/0/*)", parts.join(","))
}

fn payroll_outputs(
    psbt: &SilentPaymentPsbt,
    recipients: &[(silentpayments::SilentPaymentAddress, Amount)],
) -> Result<Vec<PayrollOutput>> {
    let mut outputs = Vec::new();
    for (idx, output) in psbt.outputs.iter().enumerate() {
        let Some((scan, spend)) = get_output_sp_info(output)? else {
            continue;
        };
        if let Some((addr, amount)) = recipients
            .iter()
            .find(|(addr, _)| addr.get_scan_key() == scan && addr.get_spend_key() == spend)
        {
            outputs.push(PayrollOutput {
                output_index: idx,
                amount: *amount,
                script_pubkey_hex: hex::encode(output.script_pubkey.as_bytes()),
                address: addr.to_string(),
            });
        }
    }
    Ok(outputs)
}
