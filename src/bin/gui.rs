use anyhow::{bail, Context, Result};
use bitcoin::{Amount, Transaction, Txid};
use serde::{Deserialize, Serialize};
use silent_pay::{
    build_initial_payroll_psbt, load_recipients, load_wallet, save_recipients, save_wallet,
    BuildInitialPayrollConfig, RecipientEntry, TreasuryPrevout, TreasurySigner,
    TreasuryWalletConfig,
};
use slint::{ComponentHandle, SharedString};
use std::fs;
use std::path::Path;
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
        in-out property <string> derivation_index: "0";
        in-out property <string> descriptor: "";
        in-out property <string> signer_table: "";
        in-out property <string> recipients_path: "recipients.toml";
        in-out property <string> recipient_rows: "";
        in-out property <string> txid: "";
        in-out property <string> vout: "0";
        in-out property <string> prevout_amount_sat: "";
        in-out property <string> prevout_path: "output/tracked-prevout.toml";
        in-out property <string> psbt_path: "output/payroll.psbt";
        in-out property <string> status: "";

        callback load_wallet();
        callback save_wallet();
        callback load_recipients();
        callback save_recipients();
        callback load_prevout();
        callback save_prevout();
        callback read_final_txid();
        callback save_psbt();

        VerticalLayout {
            padding: 14px;
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
                Text { text: "Index"; width: 70px; vertical-alignment: center; }
                LineEdit { text <=> root.derivation_index; width: 90px; }
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
    ui.run()?;
    Ok(())
}

fn load_wallet_into_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let wallet = load_wallet(ui.get_wallet_path().as_str())?;
    ui.set_wallet_network(wallet.network.into());
    ui.set_derivation_index(wallet.derivation_index.to_string().into());
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
    let picked = rfd::FileDialog::new()
        .set_file_name("payroll.psbt")
        .save_file();
    let Some(psbt_path) = picked else {
        return Ok("PSBT save canceled".to_string());
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

#[derive(Debug, Deserialize, Serialize)]
struct TrackedPrevout {
    txid: String,
    vout: u32,
    amount_sat: u64,
}

fn wallet_from_ui(ui: &PayrollGui) -> Result<TreasuryWalletConfig> {
    let descriptor = blank_to_none(ui.get_descriptor().as_str());
    if descriptor.is_none() {
        bail!("descriptor is required");
    }
    Ok(TreasuryWalletConfig {
        network: ui.get_wallet_network().to_string(),
        descriptor,
        derivation_index: ui
            .get_derivation_index()
            .as_str()
            .parse()
            .context("invalid derivation index")?,
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
