use anyhow::{anyhow, bail, Context, Result};
use bitcoin::{Address, Amount, Network, Transaction, Txid};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use copypasta::{ClipboardContext, ClipboardProvider};
use psbt::Psbt as SilentPaymentPsbt;
use serde::{Deserialize, Serialize};
use silent_pay::{
    build_initial_payroll_psbt, derive_treasury_script_pubkey, finalize_payroll, load_recipients,
    load_wallet, save_recipients, save_wallet, BuildInitialPayrollConfig, PayrollRecipient,
    RecipientEntry, TreasuryPrevout, TreasurySigner, TreasuryWalletConfig, CHANGE_CHAIN,
    RECEIVE_CHAIN,
};
use silentpayments::Network as SpNetwork;
use slint::{ComponentHandle, ModelRc, SharedString, StandardListViewItem, VecModel};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

slint::slint! {
    export { PayrollGui } from "payroll_gui.slint";
}

fn main() -> Result<()> {
    let ui = PayrollGui::new()?;
    {
        let weak = ui.as_weak();
        ui.on_save_wallet(move || set_status(&weak, save_wallet_from_ui(&weak)));
    }
    {
        let weak = ui.as_weak();
        ui.on_recalculate_receive_address(move || {
            set_status(&weak, recalculate_receive_address_from_ui(&weak))
        });
    }
    {
        let weak = ui.as_weak();
        ui.on_copy_receive_address(move || set_status(&weak, copy_receive_address_from_ui(&weak)));
    }
    {
        let weak = ui.as_weak();
        ui.on_save_utxos(move || set_status(&weak, save_utxos_from_ui(&weak)));
    }
    {
        let weak = ui.as_weak();
        ui.on_select_utxo(move |row| set_status(&weak, select_utxo_from_ui(&weak, row)));
    }
    {
        let weak = ui.as_weak();
        ui.on_add_utxo(move || set_status(&weak, add_utxo_from_ui(&weak)));
    }
    {
        let weak = ui.as_weak();
        ui.on_remove_utxo(move || set_status(&weak, remove_utxo_from_ui(&weak)));
    }
    {
        let weak = ui.as_weak();
        ui.on_browse_data_dir(move || set_status(&weak, browse_data_dir_into_ui(&weak)));
    }
    {
        let weak = ui.as_weak();
        ui.on_save_utxo_state(move || set_status(&weak, save_utxo_state_from_ui(&weak)));
    }
    {
        let weak = ui.as_weak();
        ui.on_save_recipients(move || set_status(&weak, save_recipients_from_ui(&weak)));
    }
    {
        let weak = ui.as_weak();
        ui.on_select_recipient(move |row| set_status(&weak, select_recipient_from_ui(&weak, row)));
    }
    {
        let weak = ui.as_weak();
        ui.on_add_recipient(move || set_status(&weak, add_recipient_from_ui(&weak)));
    }
    {
        let weak = ui.as_weak();
        ui.on_remove_recipient(move || set_status(&weak, remove_recipient_from_ui(&weak)));
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

    let config = load_app_config();
    ui.set_wallet_network(config.network.clone().into());
    ui.set_data_dir(config.data_dir.clone().into());
    ui.set_fee_rate_sat_vb(config.fee_rate_sat_vb.to_string().into());
    ui.set_dust_limit_sat(config.dust_limit_sat.to_string().into());
    ui.set_rpc_url(config.rpc_url.clone().into());
    ui.set_rpc_cookie_file(config.rpc_cookie_file.clone().into());
    ui.set_rpc_user(config.rpc_user.clone().into());
    ui.set_rpc_password(config.rpc_password.clone().into());
    update_fee_suggestion(&ui, 0);
    if default_network_directory(&config.network).is_some() {
        let weak = ui.as_weak();
        set_status(&weak, load_configured_network(&weak));
    }

    ui.run()?;
    Ok(())
}

fn load_configured_network(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    load_wallet_into_ui(weak)?;
    load_recipients_into_ui(weak)?;
    load_utxos_into_ui(weak)?;
    Ok("Loaded wallet, recipients, and UTXOs".to_string())
}

fn load_wallet_into_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let path = default_path_for_network(
        ui.get_wallet_network().as_str(),
        ui.get_data_dir().as_str(),
        ui.get_wallet_path().as_str(),
        "wallet.toml",
    );
    ui.set_wallet_path(path.display().to_string().into());
    let wallet = load_wallet(&path)?;
    ui.set_wallet_network(wallet.network.into());
    ui.set_last_derivation_index(wallet.last_derivation_index.to_string().into());
    ui.set_change_derivation_index(wallet.change_derivation_index.to_string().into());
    ui.set_descriptor(wallet.descriptor.unwrap_or_default().into());
    ui.set_signer_rows(signer_rows(&wallet.signers));
    update_receive_address(&ui)?;
    Ok("Loaded wallet".to_string())
}

fn save_wallet_from_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let wallet = wallet_from_ui(&ui)?;
    let path = default_path_for_network(
        wallet.network.as_str(),
        ui.get_data_dir().as_str(),
        ui.get_wallet_path().as_str(),
        "wallet.toml",
    );
    ui.set_wallet_path(path.display().to_string().into());
    save_wallet(&path, &wallet)?;
    save_app_config_from_ui(&ui)?;
    let wallet = load_wallet(&path)?;
    ui.set_descriptor(wallet.descriptor.unwrap_or_default().into());
    ui.set_signer_rows(signer_rows(&wallet.signers));
    update_receive_address(&ui)?;
    Ok("Saved wallet".to_string())
}

fn load_utxos_into_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let path = default_path_for_network(
        ui.get_wallet_network().as_str(),
        ui.get_data_dir().as_str(),
        ui.get_utxos_path().as_str(),
        "utxos.toml",
    );
    ui.set_utxos_path(path.display().to_string().into());
    let utxos = load_utxos(&path)?;
    refresh_utxo_rows(&ui, &utxos);
    Ok(format!("Loaded {} UTXOs", utxos.utxos.len()))
}

fn save_utxos_from_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let path = default_path_for_network(
        ui.get_wallet_network().as_str(),
        ui.get_data_dir().as_str(),
        ui.get_utxos_path().as_str(),
        "utxos.toml",
    );
    ui.set_utxos_path(path.display().to_string().into());
    let utxos = load_utxos_or_default(&path)?;
    save_utxos(&path, &utxos)?;
    refresh_utxo_rows(&ui, &utxos);
    Ok("Saved UTXOs".to_string())
}

fn select_utxo_from_ui(weak: &slint::Weak<PayrollGui>, row: i32) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let utxo = selected_utxo(&ui, row)?;
    ui.set_txid(utxo.txid.clone().into());
    ui.set_vout(utxo.vout.to_string().into());
    ui.set_prevout_amount_sat(utxo.amount_sat.to_string().into());
    ui.set_utxo_chain(utxo.chain.to_string().into());
    ui.set_utxo_derivation_index(utxo.derivation_index.to_string().into());
    // The receive (/0/*) and change (/1/*) counters are wallet-level and loaded
    // from the wallet; they are independent of the selected input's own index.
    update_receive_address(&ui)?;
    Ok(format!("Selected UTXO row {}", row + 1))
}

fn add_utxo_from_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let path = default_path_for_network(
        ui.get_wallet_network().as_str(),
        ui.get_data_dir().as_str(),
        ui.get_utxos_path().as_str(),
        "utxos.toml",
    );
    ui.set_utxos_path(path.display().to_string().into());
    let mut utxos = load_utxos_or_default(&path)?;
    let utxo = utxo_from_ui(&ui, UtxoStatus::Available)?;
    append_fresh_utxo(&mut utxos, utxo)?;
    save_utxos(&path, &utxos)?;
    refresh_utxo_rows(&ui, &utxos);
    Ok("Added UTXO".to_string())
}

fn remove_utxo_from_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let path = default_path_for_network(
        ui.get_wallet_network().as_str(),
        ui.get_data_dir().as_str(),
        ui.get_utxos_path().as_str(),
        "utxos.toml",
    );
    ui.set_utxos_path(path.display().to_string().into());
    let mut utxos = load_utxos(&path)?;
    let row = ui.get_selected_available_utxo_row();
    let Some(index) = available_utxo_index(&utxos, row) else {
        bail!("select a UTXO row to remove");
    };
    let utxo = &utxos.utxos[index];
    if !confirm_remove_utxo(utxo) {
        return Ok("UTXO removal canceled".to_string());
    }
    let removed = utxos.utxos.remove(index);
    save_utxos(&path, &utxos)?;
    ui.set_selected_available_utxo_row(-1);
    refresh_utxo_rows(&ui, &utxos);
    Ok(format!("Removed UTXO {}:{}", removed.txid, removed.vout))
}

fn browse_data_dir_into_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let Some(path) = rfd::FileDialog::new()
        .set_title("Select data directory")
        .pick_folder()
    else {
        return Ok("Data directory selection canceled".to_string());
    };
    ui.set_data_dir(path.display().to_string().into());
    save_app_config_from_ui(&ui)?;
    Ok("Selected data directory".to_string())
}

fn load_recipients_into_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let path = default_path_for_network(
        ui.get_wallet_network().as_str(),
        ui.get_data_dir().as_str(),
        ui.get_recipients_path().as_str(),
        "recipients.toml",
    );
    ui.set_recipients_path(path.display().to_string().into());
    let recipients = load_recipients(&path)?;
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
    ui.set_recipient_table_rows(recipient_table_rows(&recipients));
    ui.set_recipient_rows(rows.into());
    ui.set_total_payroll_sat(total_payroll_sat(&recipients).to_string().into());
    update_fee_suggestion(&ui, recipients.len());
    Ok("Loaded recipients".to_string())
}

fn save_recipients_from_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let recipients = recipient_rows(ui.get_recipient_rows().as_str())?;
    let path = default_path_for_network(
        ui.get_wallet_network().as_str(),
        ui.get_data_dir().as_str(),
        ui.get_recipients_path().as_str(),
        "recipients.toml",
    );
    ui.set_recipients_path(path.display().to_string().into());
    save_recipients(&path, &recipients)?;
    ui.set_recipient_table_rows(recipient_entry_table_rows(&recipients));
    ui.set_total_payroll_sat(total_recipient_amount_sat(&recipients).to_string().into());
    update_fee_suggestion(&ui, recipients.len());
    save_app_config_from_ui(&ui)?;
    Ok("Saved recipients".to_string())
}

fn select_recipient_from_ui(weak: &slint::Weak<PayrollGui>, row: i32) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    if row < 0 {
        return Ok("No recipient selected".to_string());
    }
    let recipients = recipient_rows(ui.get_recipient_rows().as_str())?;
    let Some(index) = selected_recipient_index(recipients.len(), row) else {
        bail!("selected recipient row is out of range");
    };
    let recipient = &recipients[index];
    ui.set_recipient_label(recipient.label.clone().unwrap_or_default().into());
    ui.set_recipient_address(recipient.address.clone().unwrap_or_default().into());
    ui.set_recipient_amount_sat(recipient.amount_sat.to_string().into());
    Ok(format!("Selected recipient row {}", row + 1))
}

fn add_recipient_from_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let mut rows = recipient_rows(ui.get_recipient_rows().as_str())?;
    let address = ui.get_recipient_address().trim().to_string();
    if address.is_empty() {
        bail!("recipient address is required");
    }
    rows.push(RecipientEntry {
        label: blank_to_none(ui.get_recipient_label().as_str()),
        amount_sat: ui
            .get_recipient_amount_sat()
            .as_str()
            .parse()
            .context("invalid recipient amount_sat")?,
        seed_hex: None,
        address: Some(address),
    });
    set_recipient_entries(&ui, &rows);
    Ok("Added recipient row".to_string())
}

fn remove_recipient_from_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let row = ui.get_selected_recipient_row();
    let mut rows = recipient_rows(ui.get_recipient_rows().as_str())?;
    let Some(index) = selected_recipient_index(rows.len(), row) else {
        bail!("select a recipient row to remove");
    };
    rows.remove(index);
    ui.set_selected_recipient_row(-1);
    set_recipient_entries(&ui, &rows);
    Ok(format!("Removed recipient row {}", row + 1))
}

fn save_psbt_from_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let psbt_path =
        match classify_psbt_save_path(ui.get_data_dir().as_str(), ui.get_psbt_path().as_str()) {
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
    let recipients_path = default_path_for_network(
        wallet.network.as_str(),
        ui.get_data_dir().as_str(),
        ui.get_recipients_path().as_str(),
        "recipients.toml",
    );
    ui.set_recipients_path(recipients_path.display().to_string().into());
    save_recipients(&recipients_path, &recipients)?;

    let prevout = TreasuryPrevout {
        txid: Txid::from_str(ui.get_txid().as_str()).context("invalid txid")?,
        vout: ui.get_vout().as_str().parse().context("invalid vout")?,
        amount: Amount::from_sat(
            ui.get_prevout_amount_sat()
                .as_str()
                .parse()
                .context("invalid prevout amount_sat")?,
        ),
        chain: parse_u32(ui.get_utxo_chain().as_str(), "UTXO chain")?,
        derivation_index: parse_u32(
            ui.get_utxo_derivation_index().as_str(),
            "UTXO derivation index",
        )?,
    };
    let fee_sat = ui
        .get_miner_fee_sat()
        .as_str()
        .parse()
        .context("invalid miner fee_sat")?;
    let mut config = BuildInitialPayrollConfig::new(wallet, &recipients_path, prevout, &psbt_path);
    config.fee = Amount::from_sat(fee_sat);
    let result = build_initial_payroll_psbt(config)?;

    Ok(format!(
        "Saved {} with {} recipients, {} sat outputs, {} sat fee, {} sat change",
        result.psbt_path.display(),
        result.recipient_count,
        result.total_output_sat,
        fee_sat,
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
    let finalize_psbt_path = data_dir_path(
        ui.get_data_dir().as_str(),
        ui.get_finalize_psbt_path().as_str(),
    );
    ui.set_finalize_psbt_path(finalize_psbt_path.display().to_string().into());
    let result = finalize_payroll(&finalize_psbt_path)
        .context("failed to finalize PSBT; make sure it contains all required contributions")?;
    let change_derivation_index = parse_u32(
        ui.get_change_derivation_index().as_str(),
        "change derivation index",
    )?;
    let change = change_prevout_from_psbt(
        &result.final_psbt_path,
        &result.txid,
        &wallet_from_ui(&ui)?,
        change_derivation_index,
    )?;
    let next_change_derivation_index = next_change_derivation_index(change.derivation_index);

    ui.set_final_txid(result.txid.clone().into());
    ui.set_pending_spent_txid(ui.get_txid());
    ui.set_pending_spent_vout(ui.get_vout());
    ui.set_pending_change_txid(result.txid.clone().into());
    ui.set_pending_change_vout(change.vout.to_string().into());
    ui.set_pending_change_amount_sat(change.amount_sat.to_string().into());
    ui.set_pending_change_derivation_index(change.derivation_index.to_string().into());
    ui.set_pending_change_label(change.label.clone().unwrap_or_default().into());
    // Change advances its own /1/* counter; the receive (/0/*) index is untouched.
    ui.set_change_derivation_index(next_change_derivation_index.to_string().into());
    update_receive_address(&ui)?;
    ui.set_final_tx_hex_path(result.final_tx_hex_path.display().to_string().into());
    ui.set_finalize_summary(
        format!(
            "txid: {}\nverified SP outputs: {}\nspent input: {}:{}\nnew change: {}:{}\nchange amount: {}\nchange derivation index: {}\nnext change derivation index: {}\nfinal PSBT: {}\nfinal tx hex: {}",
            result.txid,
            result.verified_outputs,
            ui.get_pending_spent_txid(),
            ui.get_pending_spent_vout(),
            result.txid,
            change.vout,
            change.amount_sat,
            change.derivation_index,
            next_change_derivation_index,
            result.final_psbt_path.display(),
            result.final_tx_hex_path.display()
        )
        .into(),
    );
    Ok(format!(
        "Finalized transaction {}; review and Save UTXO State",
        result.txid
    ))
}

fn save_utxo_state_from_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let path = default_path_for_network(
        ui.get_wallet_network().as_str(),
        ui.get_data_dir().as_str(),
        ui.get_utxos_path().as_str(),
        "utxos.toml",
    );
    ui.set_utxos_path(path.display().to_string().into());
    let mut utxos = load_utxos_or_default(&path)?;

    let spent_txid = ui.get_pending_spent_txid().trim().to_string();
    let spent_vout: u32 = ui
        .get_pending_spent_vout()
        .as_str()
        .parse()
        .context("invalid pending spent vout")?;
    if spent_txid.is_empty() {
        bail!("no pending finalized UTXO state to save");
    }
    mark_utxo_spent(&mut utxos, &spent_txid, spent_vout)?;

    let change = TreasuryUtxo {
        txid: ui.get_pending_change_txid().trim().to_string(),
        vout: ui
            .get_pending_change_vout()
            .as_str()
            .parse()
            .context("invalid pending change vout")?,
        amount_sat: ui
            .get_pending_change_amount_sat()
            .as_str()
            .parse()
            .context("invalid pending change amount_sat")?,
        chain: CHANGE_CHAIN,
        derivation_index: parse_u32(
            ui.get_pending_change_derivation_index().as_str(),
            "pending change derivation index",
        )?,
        status: UtxoStatus::Available,
        label: blank_to_none(ui.get_pending_change_label().as_str()),
    };
    append_fresh_utxo(&mut utxos, change)?;
    save_utxos(&path, &utxos)?;
    refresh_utxo_rows(&ui, &utxos);

    save_wallet_from_ui(weak)?;
    Ok("Saved UTXO state".to_string())
}

fn load_final_tx_hex_into_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let Some(path) = rfd::FileDialog::new()
        .set_title("Open final tx hex")
        .pick_file()
    else {
        return Ok("Final tx hex open canceled".to_string());
    };
    let tx = final_tx_from_hex_file(&path)?;
    let txid = tx.compute_txid().to_string();
    let spent = single_spent_prevout(&tx)?;
    let change_derivation_index = parse_u32(
        ui.get_change_derivation_index().as_str(),
        "change derivation index",
    )?;
    let change =
        change_prevout_from_tx(&tx, &txid, &wallet_from_ui(&ui)?, change_derivation_index)?;
    let next_change_derivation_index = next_change_derivation_index(change.derivation_index);

    ui.set_final_tx_hex_path(path.display().to_string().into());
    ui.set_final_txid(txid.clone().into());
    ui.set_pending_spent_txid(spent.txid.to_string().into());
    ui.set_pending_spent_vout(spent.vout.to_string().into());
    ui.set_pending_change_txid(txid.clone().into());
    ui.set_pending_change_vout(change.vout.to_string().into());
    ui.set_pending_change_amount_sat(change.amount_sat.to_string().into());
    ui.set_pending_change_derivation_index(change.derivation_index.to_string().into());
    ui.set_pending_change_label(change.label.clone().unwrap_or_default().into());
    // Change advances its own /1/* counter; the receive (/0/*) index is untouched.
    ui.set_change_derivation_index(next_change_derivation_index.to_string().into());
    update_receive_address(&ui)?;
    ui.set_finalize_summary(
        format!(
            "loaded final tx hex: {}\ntxid: {txid}\nspent input: {}:{}\nnew change: {}:{}\nchange amount: {}\nchange derivation index: {}\nnext change derivation index: {}",
            path.display(),
            spent.txid,
            spent.vout,
            txid,
            change.vout,
            change.amount_sat,
            change.derivation_index,
            next_change_derivation_index
        )
        .into(),
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

    let auth = rpc_auth(
        ui.get_rpc_cookie_file().as_str(),
        ui.get_rpc_user().as_str(),
        ui.get_rpc_password().as_str(),
    );
    let client =
        Client::new(ui.get_rpc_url().as_str(), auth).context("failed to create RPC client")?;
    let txid = client
        .send_raw_transaction(tx_hex)
        .context("Bitcoin Core sendrawtransaction failed")?;
    Ok(format!("Broadcast transaction {txid}"))
}

const APP_CONFIG_DIR: &str = ".silent-pay";
const CONFIG_FILE_NAME: &str = "config.toml";

#[derive(Debug, Clone, Deserialize, Serialize)]
struct AppConfig {
    #[serde(default = "default_config_network")]
    network: String,
    #[serde(default = "default_data_dir")]
    data_dir: String,
    #[serde(default = "default_fee_rate_sat_vb")]
    fee_rate_sat_vb: u64,
    #[serde(default = "default_dust_limit_sat")]
    dust_limit_sat: u64,
    #[serde(default = "default_rpc_url")]
    rpc_url: String,
    #[serde(default)]
    rpc_cookie_file: String,
    #[serde(default)]
    rpc_user: String,
    #[serde(default)]
    rpc_password: String,
}

fn default_config_network() -> String {
    "testnet".to_string()
}

fn default_data_dir() -> String {
    ".".to_string()
}

fn default_fee_rate_sat_vb() -> u64 {
    4
}

fn default_dust_limit_sat() -> u64 {
    546
}

fn default_rpc_url() -> String {
    "http://127.0.0.1:18332".to_string()
}

fn load_app_config() -> AppConfig {
    config_paths()
        .into_iter()
        .find_map(|path| {
            fs::read_to_string(path)
                .ok()
                .and_then(|contents| toml::from_str(&contents).ok())
        })
        .unwrap_or_else(default_app_config)
}

fn save_app_config_from_ui(ui: &PayrollGui) -> Result<()> {
    let fee_rate_sat_vb = ui
        .get_fee_rate_sat_vb()
        .as_str()
        .parse()
        .context("invalid fee rate sat/vB")?;
    let dust_limit_sat = ui
        .get_dust_limit_sat()
        .as_str()
        .parse()
        .context("invalid dust limit sat")?;
    let config = AppConfig {
        network: ui.get_wallet_network().to_string(),
        data_dir: ui.get_data_dir().to_string(),
        fee_rate_sat_vb,
        dust_limit_sat,
        rpc_url: ui.get_rpc_url().to_string(),
        rpc_cookie_file: ui.get_rpc_cookie_file().to_string(),
        rpc_user: ui.get_rpc_user().to_string(),
        rpc_password: ui.get_rpc_password().to_string(),
    };
    let path = write_config_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create config directory {}", parent.display()))?;
    }
    fs::write(&path, toml::to_string_pretty(&config)?)
        .with_context(|| format!("failed to write config {}", path.display()))
}

fn rpc_auth(cookie_file: &str, user: &str, password: &str) -> Auth {
    let cookie_file = cookie_file.trim();
    if !cookie_file.is_empty() {
        return Auth::CookieFile(PathBuf::from(cookie_file));
    }

    if user.is_empty() && password.is_empty() {
        Auth::None
    } else {
        Auth::UserPass(user.to_string(), password.to_string())
    }
}

fn default_app_config() -> AppConfig {
    AppConfig {
        network: default_config_network(),
        data_dir: default_data_dir(),
        fee_rate_sat_vb: default_fee_rate_sat_vb(),
        dust_limit_sat: default_dust_limit_sat(),
        rpc_url: default_rpc_url(),
        rpc_cookie_file: String::new(),
        rpc_user: String::new(),
        rpc_password: String::new(),
    }
}

fn config_paths() -> Vec<PathBuf> {
    config_paths_for_home(env::var_os("HOME"))
}

fn write_config_path() -> PathBuf {
    home_config_path().unwrap_or_else(local_config_path)
}

fn home_config_path() -> Option<PathBuf> {
    home_config_path_for_home(env::var_os("HOME"))
}

fn config_paths_for_home(home: Option<impl Into<PathBuf>>) -> Vec<PathBuf> {
    match home_config_path_for_home(home) {
        Some(path) => vec![path, local_config_path()],
        None => vec![local_config_path()],
    }
}

fn home_config_path_for_home(home: Option<impl Into<PathBuf>>) -> Option<PathBuf> {
    home.map(|home| home.into().join(APP_CONFIG_DIR).join(CONFIG_FILE_NAME))
}

fn local_config_path() -> PathBuf {
    PathBuf::from(CONFIG_FILE_NAME)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct UtxoFile {
    #[serde(default)]
    utxos: Vec<TreasuryUtxo>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct TreasuryUtxo {
    txid: String,
    vout: u32,
    amount_sat: u64,
    /// BIP-32 chain: RECEIVE_CHAIN (/0/*) or CHANGE_CHAIN (/1/*). Defaults to
    /// receive for records written before change moved to its own chain.
    #[serde(default)]
    chain: u32,
    derivation_index: u32,
    status: UtxoStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum UtxoStatus {
    Available,
    Spent,
}

fn wallet_from_ui(ui: &PayrollGui) -> Result<TreasuryWalletConfig> {
    let descriptor = blank_to_none(ui.get_descriptor().as_str());
    if descriptor.is_none() {
        bail!("descriptor is required");
    }
    Ok(TreasuryWalletConfig {
        network: ui.get_wallet_network().to_string(),
        descriptor,
        last_derivation_index: parse_u32(
            ui.get_last_derivation_index().as_str(),
            "last derivation index",
        )?,
        change_derivation_index: parse_u32(
            ui.get_change_derivation_index().as_str(),
            "change derivation index",
        )?,
        signers: Vec::new(),
    })
}

fn recalculate_receive_address_from_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    update_receive_address(&ui)?;
    Ok("Updated receive address".to_string())
}

fn copy_receive_address_from_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let address = ui.get_receive_address();
    let address = address.trim();
    if address.is_empty() {
        bail!("receive address is empty");
    }
    ClipboardContext::new()
        .map_err(|err| anyhow!("failed to access system clipboard: {err}"))?
        .set_contents(address.to_string())
        .map_err(|err| anyhow!("failed to copy receive address: {err}"))?;
    Ok("Copied receive address".to_string())
}

fn update_receive_address(ui: &PayrollGui) -> Result<()> {
    let wallet = wallet_from_ui(ui)?;
    let address = receive_address(&wallet)?;
    ui.set_receive_address(address.into());
    Ok(())
}

fn receive_address(wallet: &TreasuryWalletConfig) -> Result<String> {
    let script =
        derive_treasury_script_pubkey(wallet, RECEIVE_CHAIN, wallet.last_derivation_index)?;
    let network = bitcoin_network(wallet.network_value()?);
    Ok(Address::from_script(&script, network)?.to_string())
}

fn bitcoin_network(network: SpNetwork) -> Network {
    match network {
        SpNetwork::Mainnet => Network::Bitcoin,
        SpNetwork::Testnet => Network::Testnet,
        SpNetwork::Regtest => Network::Regtest,
    }
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

fn recipient_table_rows(recipients: &[PayrollRecipient]) -> ModelRc<ModelRc<StandardListViewItem>> {
    table_rows(recipients.iter().map(|recipient| {
        vec![
            recipient.label.clone().unwrap_or_default(),
            recipient.address.to_string(),
            recipient.amount.to_sat().to_string(),
        ]
    }))
}

fn recipient_entry_table_rows(
    recipients: &[RecipientEntry],
) -> ModelRc<ModelRc<StandardListViewItem>> {
    table_rows(recipients.iter().map(|recipient| {
        vec![
            recipient.label.clone().unwrap_or_default(),
            recipient.address.clone().unwrap_or_default(),
            recipient.amount_sat.to_string(),
        ]
    }))
}

fn set_recipient_entries(ui: &PayrollGui, recipients: &[RecipientEntry]) {
    let rows = recipients
        .iter()
        .map(|recipient| {
            format!(
                "{},{},{}",
                recipient.label.clone().unwrap_or_default(),
                recipient.address.clone().unwrap_or_default(),
                recipient.amount_sat
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    ui.set_recipient_rows(rows.into());
    ui.set_recipient_table_rows(recipient_entry_table_rows(recipients));
    ui.set_total_payroll_sat(total_recipient_amount_sat(recipients).to_string().into());
    update_fee_suggestion(ui, recipients.len());
}

fn total_payroll_sat(recipients: &[PayrollRecipient]) -> u64 {
    recipients
        .iter()
        .map(|recipient| recipient.amount.to_sat())
        .sum()
}

fn total_recipient_amount_sat(recipients: &[RecipientEntry]) -> u64 {
    recipients
        .iter()
        .map(|recipient| recipient.amount_sat)
        .sum()
}

fn selected_recipient_index(row_count: usize, row: i32) -> Option<usize> {
    if row < 0 {
        return None;
    }
    let index = row as usize;
    (index < row_count).then_some(index)
}

fn utxo_from_ui(ui: &PayrollGui, status: UtxoStatus) -> Result<TreasuryUtxo> {
    let txid = ui.get_txid().trim().to_string();
    Txid::from_str(&txid).context("invalid txid")?;
    Ok(TreasuryUtxo {
        txid: txid.as_str().to_string(),
        vout: ui.get_vout().as_str().parse().context("invalid vout")?,
        amount_sat: ui
            .get_prevout_amount_sat()
            .as_str()
            .parse()
            .context("invalid prevout amount_sat")?,
        chain: parse_u32(ui.get_utxo_chain().as_str(), "UTXO chain")?,
        derivation_index: parse_u32(
            ui.get_utxo_derivation_index().as_str(),
            "UTXO derivation index",
        )?,
        status,
        label: None,
    })
}

fn load_utxos(path: impl AsRef<Path>) -> Result<UtxoFile> {
    let path = path.as_ref();
    let contents = fs::read_to_string(path)
        .with_context(|| format!("failed to read UTXOs {}", path.display()))?;
    toml::from_str(&contents).context("failed to parse UTXOs TOML")
}

fn load_utxos_or_default(path: impl AsRef<Path>) -> Result<UtxoFile> {
    let path = path.as_ref();
    if path.exists() {
        load_utxos(path)
    } else {
        Ok(UtxoFile { utxos: Vec::new() })
    }
}

fn save_utxos(path: impl AsRef<Path>, utxos: &UtxoFile) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }
    fs::write(path, toml::to_string_pretty(utxos)?)
        .with_context(|| format!("failed to write UTXOs {}", path.display()))
}

fn refresh_utxo_rows(ui: &PayrollGui, utxos: &UtxoFile) {
    ui.set_available_utxo_rows(utxo_rows_by_status(utxos, UtxoStatus::Available));
    ui.set_spent_utxo_rows(utxo_rows_by_status(utxos, UtxoStatus::Spent));
}

fn utxo_rows_by_status(
    utxos: &UtxoFile,
    status: UtxoStatus,
) -> ModelRc<ModelRc<StandardListViewItem>> {
    table_rows(
        utxos
            .utxos
            .iter()
            .filter(|utxo| utxo.status == status)
            .map(utxo_table_row),
    )
}

fn utxo_table_row(utxo: &TreasuryUtxo) -> Vec<String> {
    vec![
        utxo.txid.clone(),
        utxo.vout.to_string(),
        utxo.amount_sat.to_string(),
        utxo.chain.to_string(),
        utxo.derivation_index.to_string(),
        utxo.label.clone().unwrap_or_default(),
    ]
}

fn selected_utxo(ui: &PayrollGui, row: i32) -> Result<TreasuryUtxo> {
    let path = default_path_for_network(
        ui.get_wallet_network().as_str(),
        ui.get_data_dir().as_str(),
        ui.get_utxos_path().as_str(),
        "utxos.toml",
    );
    let utxos = load_utxos(&path)?;
    let Some(index) = available_utxo_index(&utxos, row) else {
        bail!("selected UTXO row is out of range");
    };
    Ok(utxos.utxos[index].clone())
}

fn available_utxo_index(utxos: &UtxoFile, row: i32) -> Option<usize> {
    if row < 0 {
        return None;
    }
    utxos
        .utxos
        .iter()
        .enumerate()
        .filter(|(_, utxo)| utxo.status == UtxoStatus::Available)
        .nth(row as usize)
        .map(|(index, _)| index)
}

fn append_fresh_utxo(utxos: &mut UtxoFile, utxo: TreasuryUtxo) -> Result<()> {
    if utxos
        .utxos
        .iter()
        .any(|existing| existing.txid == utxo.txid && existing.vout == utxo.vout)
    {
        bail!("UTXO {}:{} is already recorded", utxo.txid, utxo.vout);
    }
    if utxos.utxos.iter().any(|existing| {
        existing.chain == utxo.chain && existing.derivation_index == utxo.derivation_index
    }) {
        bail!(
            "chain {} derivation index {} is already recorded",
            utxo.chain,
            utxo.derivation_index
        );
    }
    utxos.utxos.push(utxo);
    Ok(())
}

fn mark_utxo_spent(utxos: &mut UtxoFile, txid: &str, vout: u32) -> Result<()> {
    let Some(utxo) = utxos
        .utxos
        .iter_mut()
        .find(|utxo| utxo.txid == txid && utxo.vout == vout)
    else {
        bail!("spent UTXO {txid}:{vout} is not recorded");
    };
    if utxo.status == UtxoStatus::Spent {
        bail!("spent UTXO {txid}:{vout} is already marked spent");
    }
    utxo.status = UtxoStatus::Spent;
    Ok(())
}

fn change_prevout_from_psbt(
    path: impl AsRef<Path>,
    txid: &str,
    wallet: &TreasuryWalletConfig,
    derivation_index: u32,
) -> Result<TreasuryUtxo> {
    let path = path.as_ref();
    let bytes =
        fs::read(path).with_context(|| format!("failed to read PSBT {}", path.display()))?;
    let psbt = SilentPaymentPsbt::deserialize(&bytes).context("failed to parse final PSBT")?;
    let change_script = derive_treasury_script_pubkey(wallet, CHANGE_CHAIN, derivation_index)?;
    let change = psbt
        .outputs
        .iter()
        .enumerate()
        .filter(|(_, output)| output.script_pubkey == change_script)
        .map(|(vout, output)| (vout, output.amount.to_sat()))
        .collect::<Vec<_>>();
    if change.len() != 1 {
        bail!(
            "expected exactly one output matching change derivation index {derivation_index}, found {}",
            change.len()
        );
    }
    let (vout, amount_sat) = change[0];
    Ok(TreasuryUtxo {
        txid: txid.to_string(),
        vout: vout
            .try_into()
            .map_err(|_| anyhow::anyhow!("change vout does not fit u32"))?,
        amount_sat,
        chain: CHANGE_CHAIN,
        derivation_index,
        status: UtxoStatus::Available,
        label: Some("payroll change".to_string()),
    })
}

fn change_prevout_from_tx(
    tx: &Transaction,
    txid: &str,
    wallet: &TreasuryWalletConfig,
    derivation_index: u32,
) -> Result<TreasuryUtxo> {
    let change_script = derive_treasury_script_pubkey(wallet, CHANGE_CHAIN, derivation_index)?;
    let change = tx
        .output
        .iter()
        .enumerate()
        .filter(|(_, output)| output.script_pubkey == change_script)
        .map(|(vout, output)| (vout, output.value.to_sat()))
        .collect::<Vec<_>>();
    if change.len() != 1 {
        bail!(
            "expected exactly one output matching change derivation index {derivation_index}, found {}",
            change.len()
        );
    }
    let (vout, amount_sat) = change[0];
    Ok(TreasuryUtxo {
        txid: txid.to_string(),
        vout: vout
            .try_into()
            .map_err(|_| anyhow::anyhow!("change vout does not fit u32"))?,
        amount_sat,
        chain: CHANGE_CHAIN,
        derivation_index,
        status: UtxoStatus::Available,
        label: Some("payroll change".to_string()),
    })
}

fn single_spent_prevout(tx: &Transaction) -> Result<bitcoin::OutPoint> {
    if tx.input.len() != 1 {
        bail!(
            "expected exactly one input in final transaction, found {}",
            tx.input.len()
        );
    }
    Ok(tx.input[0].previous_output)
}

fn parse_u32(value: &str, label: &str) -> Result<u32> {
    value.parse().with_context(|| format!("invalid {label}"))
}

fn next_change_derivation_index(change_derivation_index: u32) -> u32 {
    change_derivation_index.saturating_add(1)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PsbtSavePath {
    Direct(PathBuf),
    NeedsDialog { directory: PathBuf },
}

fn classify_psbt_save_path(data_dir: &str, value: &str) -> PsbtSavePath {
    let value = value.trim();
    let path = data_dir_path(data_dir, value);
    if path.file_name().is_some() && path.extension().is_some() {
        return PsbtSavePath::Direct(path);
    }

    let directory = if path.as_os_str().is_empty() {
        PathBuf::from(".")
    } else if value.ends_with('/') || value.ends_with('\\') || path.is_dir() {
        path
    } else {
        path.parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    };
    PsbtSavePath::NeedsDialog { directory }
}

fn data_dir_path(data_dir: &str, value: &str) -> PathBuf {
    let path = PathBuf::from(value.trim());
    if path.is_absolute() {
        return path;
    }
    PathBuf::from(data_dir.trim()).join(path)
}

fn default_path_for_network(
    network: &str,
    data_dir: &str,
    current_path: &str,
    file_name: &str,
) -> PathBuf {
    let current = PathBuf::from(current_path.trim());
    let Some(directory) = default_network_directory(network) else {
        return current;
    };
    if is_default_file_path(&current, file_name) {
        return PathBuf::from(data_dir.trim())
            .join(directory)
            .join(file_name);
    }
    current
}

fn default_network_directory(network: &str) -> Option<&'static str> {
    let network = network.to_lowercase();
    if network.contains("testnet") {
        Some("testnet")
    } else if network.contains("mainnet") || network.contains("bitcoin") {
        Some("mainnet")
    } else {
        None
    }
}

fn is_default_file_path(path: &Path, file_name: &str) -> bool {
    if path == Path::new(file_name) {
        return true;
    }
    if file_name == "utxos.toml" && path == Path::new("output").join(file_name) {
        return true;
    }
    path.parent()
        .and_then(Path::file_name)
        .and_then(|parent| parent.to_str())
        .is_some_and(|parent| parent == "testnet" || parent == "mainnet")
        && path.file_name().and_then(|name| name.to_str()) == Some(file_name)
}

fn estimated_payroll_vbytes(recipient_count: usize) -> u64 {
    180 + 43 * recipient_count as u64
}

fn suggested_fee_sat(fee_rate_sat_vb: u64, recipient_count: usize) -> u64 {
    fee_rate_sat_vb.saturating_mul(estimated_payroll_vbytes(recipient_count))
}

fn update_fee_suggestion(ui: &PayrollGui, recipient_count: usize) {
    let fee_rate = ui
        .get_fee_rate_sat_vb()
        .as_str()
        .parse()
        .unwrap_or_else(|_| default_fee_rate_sat_vb());
    let suggested = suggested_fee_sat(fee_rate, recipient_count);
    ui.set_suggested_fee_sat(suggested.to_string().into());
    let current_fee = ui.get_miner_fee_sat();
    if current_fee.trim().is_empty() || current_fee.as_str() == "1000" {
        ui.set_miner_fee_sat(suggested.to_string().into());
    }
}

fn final_tx_from_hex_file(path: impl AsRef<Path>) -> Result<Transaction> {
    let path = path.as_ref();
    let tx_hex = fs::read_to_string(path)
        .with_context(|| format!("failed to read final tx hex {}", path.display()))?;
    let tx_bytes = hex::decode(tx_hex.trim()).context("final tx hex is not valid hex")?;
    bitcoin::consensus::encode::deserialize(&tx_bytes).context("failed to parse final tx")
}

fn signer_rows(signers: &[TreasurySigner]) -> ModelRc<ModelRc<StandardListViewItem>> {
    table_rows(signers.iter().map(|signer| {
        vec![
            signer.xfp.to_string(),
            signer.derivation_path.to_string(),
            signer.xpub.to_string(),
        ]
    }))
}

fn table_rows(
    rows: impl IntoIterator<Item = Vec<String>>,
) -> ModelRc<ModelRc<StandardListViewItem>> {
    ModelRc::new(VecModel::from(
        rows.into_iter()
            .map(|row| {
                ModelRc::new(VecModel::from(
                    row.into_iter()
                        .map(|text| StandardListViewItem::from(SharedString::from(text)))
                        .collect::<Vec<_>>(),
                ))
            })
            .collect::<Vec<_>>(),
    ))
}

fn confirm_remove_utxo(utxo: &TreasuryUtxo) -> bool {
    rfd::MessageDialog::new()
        .set_title("Remove UTXO")
        .set_description(format!(
            "Remove UTXO {}:{} from the wallet state?",
            utxo.txid, utxo.vout
        ))
        .set_buttons(rfd::MessageButtons::OkCancel)
        .set_level(rfd::MessageLevel::Warning)
        .show()
        == rfd::MessageDialogResult::Ok
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
            classify_psbt_save_path("/tmp/silent-pay", "output/payroll.psbt"),
            PsbtSavePath::Direct(PathBuf::from("/tmp/silent-pay/output/payroll.psbt"))
        );
    }

    #[test]
    fn directory_path_needs_dialog_in_that_directory() {
        assert_eq!(
            classify_psbt_save_path("/tmp/silent-pay", "output/"),
            PsbtSavePath::NeedsDialog {
                directory: PathBuf::from("/tmp/silent-pay/output/")
            }
        );
    }

    #[test]
    fn extensionless_path_needs_dialog_in_parent_directory() {
        assert_eq!(
            classify_psbt_save_path("/tmp/silent-pay", "output/payroll"),
            PsbtSavePath::NeedsDialog {
                directory: PathBuf::from("/tmp/silent-pay/output")
            }
        );
    }

    #[test]
    fn absolute_psbt_path_is_preserved() {
        assert_eq!(
            classify_psbt_save_path("/tmp/silent-pay", "/var/tmp/payroll.psbt"),
            PsbtSavePath::Direct(PathBuf::from("/var/tmp/payroll.psbt"))
        );
    }

    #[test]
    fn testnet_network_uses_testnet_default_paths() {
        assert_eq!(
            default_path_for_network("bitcoin-testnet4", ".", "wallet.toml", "wallet.toml"),
            PathBuf::from("./testnet/wallet.toml")
        );
        assert_eq!(
            default_path_for_network("testnet", ".", "recipients.toml", "recipients.toml"),
            PathBuf::from("./testnet/recipients.toml")
        );
        assert_eq!(
            default_path_for_network("testnet", ".", "output/utxos.toml", "utxos.toml"),
            PathBuf::from("./testnet/utxos.toml")
        );
    }

    #[test]
    fn mainnet_network_uses_mainnet_default_paths() {
        assert_eq!(
            default_path_for_network("mainnet", ".", "wallet.toml", "wallet.toml"),
            PathBuf::from("./mainnet/wallet.toml")
        );
        assert_eq!(
            default_path_for_network("bitcoin", ".", "recipients.toml", "recipients.toml"),
            PathBuf::from("./mainnet/recipients.toml")
        );
    }

    #[test]
    fn data_dir_roots_network_default_paths() {
        assert_eq!(
            default_path_for_network(
                "/bitcoin-testnet4",
                "/tmp/silent-pay",
                "wallet.toml",
                "wallet.toml"
            ),
            PathBuf::from("/tmp/silent-pay/testnet/wallet.toml")
        );
        assert_eq!(
            default_path_for_network(
                "mainnet",
                "/tmp/silent-pay",
                "testnet/utxos.toml",
                "utxos.toml"
            ),
            PathBuf::from("/tmp/silent-pay/mainnet/utxos.toml")
        );
    }

    #[test]
    fn explicit_custom_paths_are_preserved() {
        assert_eq!(
            default_path_for_network("testnet", ".", "archive/wallet.toml", "wallet.toml"),
            PathBuf::from("archive/wallet.toml")
        );
    }

    #[test]
    fn existing_network_default_paths_can_switch_networks() {
        assert_eq!(
            default_path_for_network("mainnet", ".", "testnet/wallet.toml", "wallet.toml"),
            PathBuf::from("./mainnet/wallet.toml")
        );
    }

    #[test]
    fn selected_utxo_advances_change_derivation_index() {
        assert_eq!(next_change_derivation_index(7), 8);
    }

    #[test]
    fn receive_address_changes_with_last_derivation_index() {
        let mut wallet = load_wallet("testnet/wallet.toml").unwrap();
        wallet.last_derivation_index = 5;
        let address_5 = receive_address(&wallet).unwrap();
        wallet.last_derivation_index = 6;
        let address_6 = receive_address(&wallet).unwrap();

        assert!(address_5.starts_with("tb1p"));
        assert!(address_6.starts_with("tb1p"));
        assert_ne!(address_5, address_6);
    }

    #[test]
    fn available_utxo_index_maps_filtered_rows_to_source_rows() {
        let utxos = UtxoFile {
            utxos: vec![
                test_utxo("spent-txid", UtxoStatus::Spent),
                test_utxo("available-a", UtxoStatus::Available),
                test_utxo("available-b", UtxoStatus::Available),
            ],
        };

        assert_eq!(available_utxo_index(&utxos, -1), None);
        assert_eq!(available_utxo_index(&utxos, 0), Some(1));
        assert_eq!(available_utxo_index(&utxos, 1), Some(2));
        assert_eq!(available_utxo_index(&utxos, 2), None);
    }

    #[test]
    fn append_fresh_utxo_allows_same_derivation_index_on_different_chains() {
        let mut utxos = UtxoFile {
            utxos: vec![test_utxo_on_chain(
                "receive-txid",
                RECEIVE_CHAIN,
                1,
                UtxoStatus::Available,
            )],
        };

        append_fresh_utxo(
            &mut utxos,
            test_utxo_on_chain("change-txid", CHANGE_CHAIN, 1, UtxoStatus::Available),
        )
        .unwrap();

        assert_eq!(utxos.utxos.len(), 2);
    }

    #[test]
    fn append_fresh_utxo_rejects_same_derivation_index_on_same_chain() {
        let mut utxos = UtxoFile {
            utxos: vec![test_utxo_on_chain(
                "first-txid",
                CHANGE_CHAIN,
                1,
                UtxoStatus::Available,
            )],
        };

        let err = append_fresh_utxo(
            &mut utxos,
            test_utxo_on_chain("second-txid", CHANGE_CHAIN, 1, UtxoStatus::Available),
        )
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "chain 1 derivation index 1 is already recorded"
        );
    }

    #[test]
    fn utxo_table_row_does_not_include_status() {
        let row = utxo_table_row(&TreasuryUtxo {
            txid: "txid".to_string(),
            vout: 1,
            amount_sat: 2,
            chain: RECEIVE_CHAIN,
            derivation_index: 3,
            status: UtxoStatus::Spent,
            label: Some("label".to_string()),
        });

        assert_eq!(row, vec!["txid", "1", "2", "0", "3", "label"]);
    }

    #[test]
    fn app_config_parses_network() {
        let config: AppConfig = toml::from_str(
            r#"
            network = "mainnet"
            data_dir = "/tmp/silent-pay"
            fee_rate_sat_vb = 7
            dust_limit_sat = 600
            rpc_url = "http://127.0.0.1:8332"
            rpc_cookie_file = "/tmp/bitcoin/.cookie"
            rpc_user = "user"
            rpc_password = "password"
            "#,
        )
        .unwrap();
        assert_eq!(config.network, "mainnet");
        assert_eq!(config.data_dir, "/tmp/silent-pay");
        assert_eq!(config.fee_rate_sat_vb, 7);
        assert_eq!(config.dust_limit_sat, 600);
        assert_eq!(config.rpc_url, "http://127.0.0.1:8332");
        assert_eq!(config.rpc_cookie_file, "/tmp/bitcoin/.cookie");
        assert_eq!(config.rpc_user, "user");
        assert_eq!(config.rpc_password, "password");
    }

    #[test]
    fn app_config_defaults_when_empty() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert_eq!(config.network, "testnet");
        assert_eq!(config.data_dir, ".");
        assert_eq!(config.fee_rate_sat_vb, 4);
        assert_eq!(config.dust_limit_sat, 546);
        assert_eq!(config.rpc_url, "http://127.0.0.1:18332");
        assert_eq!(config.rpc_cookie_file, "");
        assert_eq!(config.rpc_user, "");
        assert_eq!(config.rpc_password, "");
    }

    #[test]
    fn config_paths_prefer_home_config_then_local_config() {
        assert_eq!(
            config_paths_for_home(Some(PathBuf::from("/home/macgyver"))),
            vec![
                PathBuf::from("/home/macgyver/.silent-pay/config.toml"),
                PathBuf::from("config.toml")
            ]
        );
    }

    #[test]
    fn config_paths_use_local_config_without_home() {
        assert_eq!(
            config_paths_for_home(None::<PathBuf>),
            vec![PathBuf::from("config.toml")]
        );
    }

    #[test]
    fn rpc_auth_uses_cookie_file_when_present() {
        match rpc_auth(" /tmp/bitcoin/.cookie ", "user", "password") {
            Auth::CookieFile(path) => assert_eq!(path, PathBuf::from("/tmp/bitcoin/.cookie")),
            auth => panic!("expected cookie auth, got {auth:?}"),
        }
    }

    #[test]
    fn rpc_auth_uses_user_pass_without_cookie_file() {
        match rpc_auth("", "user", "password") {
            Auth::UserPass(user, password) => {
                assert_eq!(user, "user");
                assert_eq!(password, "password");
            }
            auth => panic!("expected user/password auth, got {auth:?}"),
        }
    }

    #[test]
    fn selected_recipient_index_rejects_out_of_range_rows() {
        assert_eq!(selected_recipient_index(2, -1), None);
        assert_eq!(selected_recipient_index(2, 0), Some(0));
        assert_eq!(selected_recipient_index(2, 1), Some(1));
        assert_eq!(selected_recipient_index(2, 2), None);
    }

    #[test]
    fn total_recipient_amount_sums_recipient_rows() {
        let recipients = vec![
            RecipientEntry {
                label: None,
                seed_hex: None,
                address: Some("tb1recipient1".to_string()),
                amount_sat: 1_000,
            },
            RecipientEntry {
                label: Some("second".to_string()),
                seed_hex: None,
                address: Some("tb1recipient2".to_string()),
                amount_sat: 2_500,
            },
        ];

        assert_eq!(total_recipient_amount_sat(&recipients), 3_500);
    }

    #[test]
    fn fee_suggestion_scales_by_recipient_count() {
        assert_eq!(suggested_fee_sat(4, 0), 720);
        assert_eq!(suggested_fee_sat(4, 1), 892);
        assert_eq!(suggested_fee_sat(4, 3), 1236);
    }

    fn test_utxo(txid: &str, status: UtxoStatus) -> TreasuryUtxo {
        test_utxo_on_chain(txid, RECEIVE_CHAIN, 0, status)
    }

    fn test_utxo_on_chain(
        txid: &str,
        chain: u32,
        derivation_index: u32,
        status: UtxoStatus,
    ) -> TreasuryUtxo {
        TreasuryUtxo {
            txid: txid.to_string(),
            vout: 0,
            amount_sat: 1_000,
            chain,
            derivation_index,
            status,
            label: None,
        }
    }
}
