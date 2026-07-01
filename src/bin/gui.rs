use anyhow::{bail, Context, Result};
use bitcoin::{Amount, Transaction, Txid};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use psbt::Psbt as SilentPaymentPsbt;
use serde::{Deserialize, Serialize};
use silent_pay::{
    build_initial_payroll_psbt, finalize_payroll, load_recipients, load_wallet, save_recipients,
    save_wallet, BuildInitialPayrollConfig, RecipientEntry, TreasuryPrevout, TreasurySigner,
    TreasuryWalletConfig,
};
use slint::{ComponentHandle, SharedString};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

slint::slint! {
    import { Button, LineEdit, TextEdit } from "std-widgets.slint";

    export component PayrollGui inherits Window {
        title: "Silent Pay";
        preferred-width: 1274px;
        preferred-height: 1028px;
        min-width: 760px;
        min-height: 640px;
        max-width: 4096px;
        max-height: 4096px;

        in-out property <string> wallet_path: "wallet.toml";
        in-out property <string> wallet_network: "testnet";
        in-out property <string> input_derivation_index: "0";
        in-out property <string> change_derivation_index: "1";
        in-out property <string> descriptor: "";
        in-out property <string> signer_table: "";
        in-out property <string> recipients_path: "recipients.toml";
        in-out property <string> recipient_rows: "";
        in-out property <string> txid: "";
        in-out property <string> vout: "0";
        in-out property <string> prevout_amount_sat: "";
        in-out property <string> prevout_path: "output/tracked-prevout.toml";
        in-out property <string> psbt_path: "output/payroll.psbt";
        in-out property <int> active_tab: 0;
        in-out property <string> finalize_psbt_path: "output/pay/musig2-sp-cosigner-contrib.psbt";
        in-out property <string> final_tx_hex_path: "";
        in-out property <string> final_txid: "";
        in-out property <string> finalize_summary: "";
        in-out property <string> rpc_url: "http://127.0.0.1:18332";
        in-out property <string> rpc_user: "";
        in-out property <string> rpc_password: "";
        in-out property <string> status: "";

        callback load_wallet();
        callback save_wallet();
        callback load_recipients();
        callback save_recipients();
        callback load_prevout();
        callback save_prevout();
        callback read_final_txid();
        callback save_psbt();
        callback pick_finalize_psbt();
        callback finalize_loaded_psbt();
        callback load_final_tx_hex();
        callback broadcast_final_tx();

        VerticalLayout {
            padding: 14px;
            spacing: 12px;

            HorizontalLayout {
                spacing: 8px;
                Button { text: "Build"; clicked => { root.active_tab = 0; } }
                Button { text: "Finalize / Broadcast"; clicked => { root.active_tab = 1; } }
            }

            if root.active_tab == 0 : VerticalLayout {
                spacing: 12px;

                Text { text: "Wallet"; font-size: 20px; }
                HorizontalLayout {
                    spacing: 8px;
                    Text { text: "File"; width: 110px; vertical-alignment: center; }
                    LineEdit { text <=> root.wallet_path; }
                    Button { text: "Load"; clicked => { root.load_wallet(); } }
                    Button { text: "Save"; clicked => { root.save_wallet(); } }
                }
                HorizontalLayout {
                    spacing: 8px;
                    Text { text: "Network"; width: 110px; vertical-alignment: center; }
                    LineEdit { text <=> root.wallet_network; width: 130px; }
                    Text { text: "Input Index"; width: 100px; vertical-alignment: center; }
                    LineEdit { text <=> root.input_derivation_index; width: 90px; }
                    Text { text: "Change Index"; width: 110px; vertical-alignment: center; }
                    LineEdit { text <=> root.change_derivation_index; width: 90px; }
                }
                Text { text: "Descriptor"; }
                TextEdit { text <=> root.descriptor; height: 170px; }
                Text { text: "Signers"; }
                Rectangle {
                    border-width: 1px;
                    border-color: #c8c8c8;
                    background: #f8f8f8;
                    height: 110px;
                    Text {
                        text: root.signer_table;
                        font-family: "monospace";
                        font-size: 13px;
                        color: #222;
                        x: 8px;
                        y: 8px;
                        width: parent.width - 16px;
                        height: parent.height - 16px;
                        wrap: no-wrap;
                    }
                }

                Text { text: "Recipients"; font-size: 20px; }
                HorizontalLayout {
                    spacing: 8px;
                    Text { text: "File"; width: 110px; vertical-alignment: center; }
                    LineEdit { text <=> root.recipients_path; }
                    Button { text: "Load"; clicked => { root.load_recipients(); } }
                    Button { text: "Save"; clicked => { root.save_recipients(); } }
                }
                Text { text: "Rows: label,address,amount_sat"; }
                TextEdit { text <=> root.recipient_rows; height: 150px; }

                Text { text: "Payroll"; font-size: 20px; }
                HorizontalLayout {
                    spacing: 8px;
                    Text { text: "Prevout File"; width: 110px; vertical-alignment: center; }
                    LineEdit { text <=> root.prevout_path; }
                    Button { text: "Load"; clicked => { root.load_prevout(); } }
                    Button { text: "Save"; clicked => { root.save_prevout(); } }
                }
                HorizontalLayout {
                    spacing: 8px;
                    Text { text: "Txid"; width: 110px; vertical-alignment: center; }
                    LineEdit { text <=> root.txid; }
                    Button { text: "Read Final Tx"; clicked => { root.read_final_txid(); } }
                }
                HorizontalLayout {
                    spacing: 8px;
                    Text { text: "Vout"; width: 110px; vertical-alignment: center; }
                    LineEdit { text <=> root.vout; width: 90px; }
                    Text { text: "Amount sat"; width: 110px; vertical-alignment: center; }
                    LineEdit { text <=> root.prevout_amount_sat; width: 170px; }
                }
                HorizontalLayout {
                    spacing: 8px;
                    Text { text: "PSBT"; width: 110px; vertical-alignment: center; }
                    LineEdit { text <=> root.psbt_path; }
                    Button { text: "Save PSBT"; clicked => { root.save_psbt(); } }
                }
            }

            if root.active_tab == 1 : VerticalLayout {
                spacing: 12px;

                Text { text: "Finalize"; font-size: 20px; }
                HorizontalLayout {
                    spacing: 8px;
                    Text { text: "Signed PSBT"; width: 110px; vertical-alignment: center; }
                    LineEdit { text <=> root.finalize_psbt_path; }
                    Button { text: "Browse"; clicked => { root.pick_finalize_psbt(); } }
                    Button { text: "Finalize"; clicked => { root.finalize_loaded_psbt(); } }
                }
                HorizontalLayout {
                    spacing: 8px;
                    Text { text: "Final Tx Hex"; width: 110px; vertical-alignment: center; }
                    LineEdit { text <=> root.final_tx_hex_path; }
                    Button { text: "Load Tx Hex"; clicked => { root.load_final_tx_hex(); } }
                }
                HorizontalLayout {
                    spacing: 8px;
                    Text { text: "Txid"; width: 110px; vertical-alignment: center; }
                    LineEdit { text <=> root.final_txid; }
                }
                TextEdit { text <=> root.finalize_summary; height: 120px; }

                Text { text: "Next Prevout"; font-size: 20px; }
                HorizontalLayout {
                    spacing: 8px;
                    Text { text: "Prevout File"; width: 110px; vertical-alignment: center; }
                    LineEdit { text <=> root.prevout_path; }
                    Button { text: "Save"; clicked => { root.save_prevout(); } }
                }
                HorizontalLayout {
                    spacing: 8px;
                    Text { text: "Vout"; width: 110px; vertical-alignment: center; }
                    LineEdit { text <=> root.vout; width: 90px; }
                    Text { text: "Amount sat"; width: 110px; vertical-alignment: center; }
                    LineEdit { text <=> root.prevout_amount_sat; width: 170px; }
                }

                Text { text: "Broadcast"; font-size: 20px; }
                HorizontalLayout {
                    spacing: 8px;
                    Text { text: "RPC URL"; width: 110px; vertical-alignment: center; }
                    LineEdit { text <=> root.rpc_url; }
                }
                HorizontalLayout {
                    spacing: 8px;
                    Text { text: "RPC User"; width: 110px; vertical-alignment: center; }
                    LineEdit { text <=> root.rpc_user; }
                    Text { text: "Password"; width: 90px; vertical-alignment: center; }
                    LineEdit { text <=> root.rpc_password; }
                    Button { text: "Broadcast"; clicked => { root.broadcast_final_tx(); } }
                }
            }

            Text { text: root.status; color: #a33; wrap: word-wrap; }
        }
    }
}

fn main() -> Result<()> {
    let ui = PayrollGui::new()?;
    {
        let weak = ui.as_weak();
        ui.on_load_wallet(move || set_status(&weak, load_wallet_into_ui(&weak)));
    }
    {
        let weak = ui.as_weak();
        ui.on_save_wallet(move || set_status(&weak, save_wallet_from_ui(&weak)));
    }
    {
        let weak = ui.as_weak();
        ui.on_load_recipients(move || set_status(&weak, load_recipients_into_ui(&weak)));
    }
    {
        let weak = ui.as_weak();
        ui.on_save_recipients(move || set_status(&weak, save_recipients_from_ui(&weak)));
    }
    {
        let weak = ui.as_weak();
        ui.on_load_prevout(move || set_status(&weak, load_prevout_into_ui(&weak)));
    }
    {
        let weak = ui.as_weak();
        ui.on_save_prevout(move || set_status(&weak, save_prevout_from_ui(&weak)));
    }
    {
        let weak = ui.as_weak();
        ui.on_read_final_txid(move || set_status(&weak, read_final_txid_into_ui(&weak)));
    }
    {
        let weak = ui.as_weak();
        ui.on_save_psbt(move || set_status(&weak, save_psbt_from_ui(&weak)));
    }
    {
        let weak = ui.as_weak();
        ui.on_pick_finalize_psbt(move || set_status(&weak, pick_finalize_psbt_into_ui(&weak)));
    }
    {
        let weak = ui.as_weak();
        ui.on_finalize_loaded_psbt(move || set_status(&weak, finalize_loaded_psbt_from_ui(&weak)));
    }
    {
        let weak = ui.as_weak();
        ui.on_load_final_tx_hex(move || set_status(&weak, load_final_tx_hex_into_ui(&weak)));
    }
    {
        let weak = ui.as_weak();
        ui.on_broadcast_final_tx(move || set_status(&weak, broadcast_final_tx_from_ui(&weak)));
    }
    ui.run()?;
    Ok(())
}

fn load_wallet_into_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let wallet = load_wallet(ui.get_wallet_path().as_str())?;
    ui.set_wallet_network(wallet.network.into());
    ui.set_input_derivation_index(wallet.input_derivation_index.to_string().into());
    ui.set_change_derivation_index(wallet.change_derivation_index.to_string().into());
    ui.set_descriptor(wallet.descriptor.unwrap_or_default().into());
    ui.set_signer_table(format_signers(&wallet.signers).into());
    Ok("Loaded wallet".to_string())
}

fn save_wallet_from_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let wallet = wallet_from_ui(&ui)?;
    save_wallet(ui.get_wallet_path().as_str(), &wallet)?;
    let wallet = load_wallet(ui.get_wallet_path().as_str())?;
    ui.set_descriptor(wallet.descriptor.unwrap_or_default().into());
    ui.set_signer_table(format_signers(&wallet.signers).into());
    Ok("Saved wallet".to_string())
}

fn load_recipients_into_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let recipients = load_recipients(ui.get_recipients_path().as_str())?;
    let rows = recipients
        .iter()
        .map(|recipient| {
            format!(
                "{},{},{}",
                recipient.label.clone().unwrap_or_default(),
                recipient.address,
                recipient.amount.to_sat()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    ui.set_recipient_rows(rows.into());
    Ok("Loaded recipients".to_string())
}

fn save_recipients_from_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let recipients = recipient_rows(ui.get_recipient_rows().as_str())?;
    save_recipients(ui.get_recipients_path().as_str(), &recipients)?;
    Ok("Saved recipients".to_string())
}

fn load_prevout_into_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let tracked = load_tracked_prevout(ui.get_prevout_path().as_str())?;
    ui.set_txid(tracked.txid.into());
    ui.set_vout(tracked.vout.to_string().into());
    ui.set_prevout_amount_sat(tracked.amount_sat.to_string().into());
    ui.set_input_derivation_index(tracked.derivation_index.to_string().into());
    Ok("Loaded tracked prevout".to_string())
}

fn save_prevout_from_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let tracked = tracked_prevout_from_ui(&ui)?;
    save_tracked_prevout(ui.get_prevout_path().as_str(), &tracked)?;
    Ok("Saved tracked prevout".to_string())
}

fn read_final_txid_into_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let Some(path) = rfd::FileDialog::new()
        .set_title("Open final tx hex")
        .pick_file()
    else {
        return Ok("Final tx read canceled".to_string());
    };
    let tx_hex = fs::read_to_string(&path)
        .with_context(|| format!("failed to read final tx hex {}", path.display()))?;
    let tx_bytes = hex::decode(tx_hex.trim()).context("final tx hex is not valid hex")?;
    let tx: Transaction =
        bitcoin::consensus::encode::deserialize(&tx_bytes).context("failed to parse final tx")?;
    let txid = tx.compute_txid().to_string();
    ui.set_txid(txid.clone().into());

    if let Ok(tracked) = tracked_prevout_from_ui(&ui) {
        save_tracked_prevout(ui.get_prevout_path().as_str(), &tracked)?;
        Ok(format!(
            "Read txid from {} and saved tracked prevout",
            path.display()
        ))
    } else {
        Ok(format!(
            "Read txid from {}; enter vout and amount, then Save",
            path.display()
        ))
    }
}

fn save_psbt_from_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let psbt_path = match classify_psbt_save_path(ui.get_psbt_path().as_str()) {
        PsbtSavePath::Direct(path) => path,
        PsbtSavePath::NeedsDialog { directory } => {
            let picked = rfd::FileDialog::new()
                .set_directory(directory)
                .set_file_name("payroll.psbt")
                .save_file();
            let Some(path) = picked else {
                return Ok("PSBT save canceled".to_string());
            };
            path
        }
    };
    ui.set_psbt_path(psbt_path.display().to_string().into());

    let wallet = wallet_from_ui(&ui)?;
    let recipients = recipient_rows(ui.get_recipient_rows().as_str())?;
    save_recipients(ui.get_recipients_path().as_str(), &recipients)?;

    let prevout = TreasuryPrevout {
        txid: Txid::from_str(ui.get_txid().as_str()).context("invalid txid")?,
        vout: ui.get_vout().as_str().parse().context("invalid vout")?,
        amount: Amount::from_sat(
            ui.get_prevout_amount_sat()
                .as_str()
                .parse()
                .context("invalid prevout amount_sat")?,
        ),
    };
    let result = build_initial_payroll_psbt(BuildInitialPayrollConfig::new(
        wallet,
        ui.get_recipients_path().as_str(),
        prevout,
        &psbt_path,
    ))?;

    Ok(format!(
        "Saved {} with {} recipients, {} sat outputs, {} sat change",
        result.psbt_path.display(),
        result.recipient_count,
        result.total_output_sat,
        result.change_sat
    ))
}

fn pick_finalize_psbt_into_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let Some(path) = rfd::FileDialog::new()
        .set_title("Open signed PSBT")
        .pick_file()
    else {
        return Ok("PSBT open canceled".to_string());
    };
    ui.set_finalize_psbt_path(path.display().to_string().into());
    Ok("Selected signed PSBT".to_string())
}

fn finalize_loaded_psbt_from_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let result = finalize_payroll(ui.get_finalize_psbt_path().as_str())
        .context("failed to finalize PSBT; make sure it contains all required contributions")?;
    let change_derivation_index = parse_u32(
        ui.get_change_derivation_index().as_str(),
        "change derivation index",
    )?;
    let change = change_prevout_from_psbt(
        &result.final_psbt_path,
        &result.txid,
        change_derivation_index,
    )?;
    save_tracked_prevout(ui.get_prevout_path().as_str(), &change)?;
    let next_change_derivation_index = change.derivation_index.saturating_add(1);

    ui.set_final_txid(result.txid.clone().into());
    ui.set_txid(result.txid.clone().into());
    ui.set_vout(change.vout.to_string().into());
    ui.set_prevout_amount_sat(change.amount_sat.to_string().into());
    ui.set_input_derivation_index(change.derivation_index.to_string().into());
    ui.set_change_derivation_index(next_change_derivation_index.to_string().into());
    ui.set_final_tx_hex_path(result.final_tx_hex_path.display().to_string().into());
    ui.set_finalize_summary(
        format!(
            "txid: {}\nverified SP outputs: {}\nchange vout: {}\nchange amount: {}\nchange derivation index: {}\nnext change derivation index: {}\ntracked prevout: {}\nfinal PSBT: {}\nfinal tx hex: {}",
            result.txid,
            result.verified_outputs,
            change.vout,
            change.amount_sat,
            change.derivation_index,
            next_change_derivation_index,
            ui.get_prevout_path(),
            result.final_psbt_path.display(),
            result.final_tx_hex_path.display()
        )
        .into(),
    );
    Ok(format!(
        "Finalized transaction {} and saved change prevout",
        result.txid
    ))
}

fn load_final_tx_hex_into_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let Some(path) = rfd::FileDialog::new()
        .set_title("Open final tx hex")
        .pick_file()
    else {
        return Ok("Final tx hex open canceled".to_string());
    };
    let txid = txid_from_hex_file(&path)?;
    ui.set_final_tx_hex_path(path.display().to_string().into());
    ui.set_final_txid(txid.clone().into());
    ui.set_txid(txid.clone().into());
    ui.set_finalize_summary(
        format!("loaded final tx hex: {}\ntxid: {txid}", path.display()).into(),
    );
    Ok("Loaded final tx hex".to_string())
}

fn broadcast_final_tx_from_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let tx_hex_path = ui.get_final_tx_hex_path();
    let tx_hex = fs::read_to_string(tx_hex_path.as_str())
        .with_context(|| format!("failed to read final tx hex {}", tx_hex_path))?;
    let tx_hex = tx_hex.trim().to_string();
    if tx_hex.is_empty() {
        bail!("final tx hex path is empty or contains no transaction hex");
    }

    let auth = if ui.get_rpc_user().is_empty() && ui.get_rpc_password().is_empty() {
        Auth::None
    } else {
        Auth::UserPass(
            ui.get_rpc_user().to_string(),
            ui.get_rpc_password().to_string(),
        )
    };
    let client =
        Client::new(ui.get_rpc_url().as_str(), auth).context("failed to create RPC client")?;
    let txid = client
        .send_raw_transaction(tx_hex)
        .context("Bitcoin Core sendrawtransaction failed")?;
    Ok(format!("Broadcast transaction {txid}"))
}

#[derive(Debug, Deserialize, Serialize)]
struct TrackedPrevout {
    txid: String,
    vout: u32,
    amount_sat: u64,
    #[serde(default)]
    derivation_index: u32,
}

fn wallet_from_ui(ui: &PayrollGui) -> Result<TreasuryWalletConfig> {
    let descriptor = blank_to_none(ui.get_descriptor().as_str());
    if descriptor.is_none() {
        bail!("descriptor is required");
    }
    Ok(TreasuryWalletConfig {
        network: ui.get_wallet_network().to_string(),
        descriptor,
        input_derivation_index: parse_u32(
            ui.get_input_derivation_index().as_str(),
            "input derivation index",
        )?,
        change_derivation_index: parse_u32(
            ui.get_change_derivation_index().as_str(),
            "change derivation index",
        )?,
        signers: Vec::new(),
    })
}

fn recipient_rows(rows: &str) -> Result<Vec<RecipientEntry>> {
    let mut recipients = Vec::new();
    for (idx, line) in rows.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<_> = line.splitn(3, ',').map(str::trim).collect();
        if parts.len() != 3 {
            bail!("recipient row {} must be label,address,amount_sat", idx + 1);
        }
        recipients.push(RecipientEntry {
            label: blank_to_none(parts[0]),
            amount_sat: parts[2]
                .parse()
                .with_context(|| format!("recipient row {} has invalid amount_sat", idx + 1))?,
            seed_hex: None,
            address: Some(parts[1].to_string()),
        });
    }
    Ok(recipients)
}

fn tracked_prevout_from_ui(ui: &PayrollGui) -> Result<TrackedPrevout> {
    let txid = ui.get_txid().trim().to_string();
    Txid::from_str(&txid).context("invalid txid")?;
    Ok(TrackedPrevout {
        txid,
        vout: ui.get_vout().as_str().parse().context("invalid vout")?,
        amount_sat: ui
            .get_prevout_amount_sat()
            .as_str()
            .parse()
            .context("invalid prevout amount_sat")?,
        derivation_index: parse_u32(
            ui.get_input_derivation_index().as_str(),
            "input derivation index",
        )?,
    })
}

fn load_tracked_prevout(path: impl AsRef<Path>) -> Result<TrackedPrevout> {
    let path = path.as_ref();
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read tracked prevout {}", path.display()))?;
    toml::from_str(&contents).context("failed to parse tracked prevout TOML")
}

fn save_tracked_prevout(path: impl AsRef<Path>, tracked: &TrackedPrevout) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }
    fs::write(path, toml::to_string_pretty(tracked)?)
        .with_context(|| format!("failed to write tracked prevout {}", path.display()))
}

fn change_prevout_from_psbt(
    path: impl AsRef<Path>,
    txid: &str,
    derivation_index: u32,
) -> Result<TrackedPrevout> {
    let path = path.as_ref();
    let bytes =
        fs::read(path).with_context(|| format!("failed to read PSBT {}", path.display()))?;
    let psbt = SilentPaymentPsbt::deserialize(&bytes).context("failed to parse final PSBT")?;
    let change = psbt
        .outputs
        .iter()
        .enumerate()
        .filter(|(_, output)| output.sp_v0_info.is_none())
        .map(|(vout, output)| (vout, output.amount.to_sat()))
        .collect::<Vec<_>>();
    if change.len() != 1 {
        bail!(
            "expected exactly one change output in final PSBT, found {}",
            change.len()
        );
    }
    let (vout, amount_sat) = change[0];
    Ok(TrackedPrevout {
        txid: txid.to_string(),
        vout: vout
            .try_into()
            .map_err(|_| anyhow::anyhow!("change vout does not fit u32"))?,
        amount_sat,
        derivation_index,
    })
}

fn parse_u32(value: &str, label: &str) -> Result<u32> {
    value.parse().with_context(|| format!("invalid {label}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PsbtSavePath {
    Direct(PathBuf),
    NeedsDialog { directory: PathBuf },
}

fn classify_psbt_save_path(value: &str) -> PsbtSavePath {
    let path = PathBuf::from(value.trim());
    if path.file_name().is_some() && path.extension().is_some() {
        return PsbtSavePath::Direct(path);
    }

    let directory = if path.as_os_str().is_empty() {
        PathBuf::from(".")
    } else if path.is_dir() {
        path
    } else {
        path.parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    };
    PsbtSavePath::NeedsDialog { directory }
}

fn txid_from_hex_file(path: impl AsRef<Path>) -> Result<String> {
    let path = path.as_ref();
    let tx_hex = fs::read_to_string(path)
        .with_context(|| format!("failed to read final tx hex {}", path.display()))?;
    let tx_bytes = hex::decode(tx_hex.trim()).context("final tx hex is not valid hex")?;
    let tx: Transaction =
        bitcoin::consensus::encode::deserialize(&tx_bytes).context("failed to parse final tx")?;
    Ok(tx.compute_txid().to_string())
}

fn format_signers(signers: &[TreasurySigner]) -> String {
    let rows = signers
        .iter()
        .map(|signer| {
            format!(
                "{:<10} {:<22} {}",
                signer.xfp,
                signer.derivation_path,
                partial_xpub(&signer.xpub)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!("{:<10} {:<22} {}\n{}", "xfp", "derivation", "xpub", rows)
}

fn partial_xpub(xpub: &str) -> String {
    if xpub.len() <= 34 {
        return xpub.to_string();
    }
    format!("{}...{}", &xpub[..18], &xpub[xpub.len() - 13..])
}

fn blank_to_none(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn set_status(weak: &slint::Weak<PayrollGui>, result: Result<String>) {
    if let Some(ui) = weak.upgrade() {
        let message = match result {
            Ok(message) => message,
            Err(err) => format!("{err:#}"),
        };
        ui.set_status(SharedString::from(message));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_psbt_path_saves_directly() {
        assert_eq!(
            classify_psbt_save_path("output/payroll.psbt"),
            PsbtSavePath::Direct(PathBuf::from("output/payroll.psbt"))
        );
    }

    #[test]
    fn directory_path_needs_dialog_in_that_directory() {
        assert_eq!(
            classify_psbt_save_path("output/"),
            PsbtSavePath::NeedsDialog {
                directory: PathBuf::from("output/")
            }
        );
    }

    #[test]
    fn extensionless_path_needs_dialog_in_parent_directory() {
        assert_eq!(
            classify_psbt_save_path("output/payroll"),
            PsbtSavePath::NeedsDialog {
                directory: PathBuf::from("output")
            }
        );
    }
}
