use anyhow::{bail, Context, Result};
use bitcoin::{Amount, Transaction, Txid};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use psbt::Psbt as SilentPaymentPsbt;
use serde::{Deserialize, Serialize};
use silent_pay::{
    build_initial_payroll_psbt, derive_treasury_script_pubkey, finalize_payroll, load_recipients,
    load_wallet, save_recipients, save_wallet, BuildInitialPayrollConfig, PayrollRecipient,
    RecipientEntry, TreasuryPrevout, TreasurySigner, TreasuryWalletConfig,
};
use slint::{ComponentHandle, ModelRc, SharedString, StandardListViewItem, VecModel};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

slint::slint! {
    import { Button, LineEdit, StandardTableView, TextEdit } from "std-widgets.slint";

    export component PayrollGui inherits Window {
        title: "Silent Pay";
        preferred-width: 1274px;
        preferred-height: 760px;
        min-width: 760px;
        min-height: 640px;
        max-width: 4096px;
        max-height: 4096px;

        in-out property <string> wallet_path: "testnet/wallet.toml";
        in-out property <string> wallet_network: "testnet";
        in-out property <string> last_derivation_index: "0";
        in-out property <string> change_derivation_index: "1";
        in-out property <string> utxo_derivation_index: "0";
        in-out property <string> descriptor: "";
        in-out property <[[StandardListViewItem]]> signer_rows;
        in-out property <string> utxos_path: "testnet/utxos.toml";
        in-out property <[[StandardListViewItem]]> available_utxo_rows;
        in-out property <[[StandardListViewItem]]> spent_utxo_rows;
        in-out property <int> selected_available_utxo_row: -1;
        in-out property <int> active_utxo_tab: 0;
        in-out property <bool> show_utxos: true;
        in-out property <bool> show_recipients: true;
        in-out property <string> pending_spent_txid: "";
        in-out property <string> pending_spent_vout: "";
        in-out property <string> pending_change_txid: "";
        in-out property <string> pending_change_vout: "";
        in-out property <string> pending_change_amount_sat: "";
        in-out property <string> pending_change_derivation_index: "";
        in-out property <string> pending_change_label: "payroll change";
        in-out property <string> recipients_path: "testnet/recipients.toml";
        in-out property <string> recipient_rows: "";
        in-out property <[[StandardListViewItem]]> recipient_table_rows;
        in-out property <string> txid: "";
        in-out property <string> vout: "0";
        in-out property <string> prevout_amount_sat: "";
        in-out property <string> miner_fee_sat: "1000";
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
        callback load_utxos();
        callback save_utxos();
        callback select_utxo(int);
        callback add_utxo();
        callback remove_utxo();
        callback save_utxo_state();
        callback load_recipients();
        callback save_recipients();
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
                Button { text: "Config"; clicked => { root.active_tab = 1; } }
                Button { text: "Finalize / Broadcast"; clicked => { root.active_tab = 2; } }
            }

            if root.active_tab == 0 : VerticalLayout {
                spacing: 12px;

                HorizontalLayout {
                    spacing: 8px;
                    Text { text: "UTXOs"; font-size: 20px; vertical-alignment: center; }
                    Button {
                        text: root.show_utxos ? "Hide" : "Show";
                        clicked => { root.show_utxos = !root.show_utxos; }
                    }
                }
                if root.show_utxos : VerticalLayout {
                    spacing: 12px;
                    HorizontalLayout {
                        spacing: 8px;
                        Text { text: "File"; width: 110px; vertical-alignment: center; }
                        LineEdit { text <=> root.utxos_path; }
                        Button { text: "Load"; clicked => { root.load_utxos(); } }
                        Button { text: "Save"; clicked => { root.save_utxos(); } }
                    }
                    HorizontalLayout {
                        spacing: 8px;
                        Button { text: "UTXOs"; clicked => { root.active_utxo_tab = 0; } }
                        Button { text: "History"; clicked => { root.active_utxo_tab = 1; } }
                    }
                    if root.active_utxo_tab == 0 : VerticalLayout {
                        spacing: 12px;
                        StandardTableView {
                            height: 170px;
                            rows <=> root.available_utxo_rows;
                            current-row <=> root.selected_available_utxo_row;
                            columns: [
                                { title: "Txid", min-width: 560px, width: 570px, horizontal-stretch: 1 },
                                { title: "Vout", min-width: 90px, width: 90px, horizontal-stretch: 0 },
                                { title: "Amount sat", min-width: 120px, width: 130px, horizontal-stretch: 0 },
                                { title: "Index", min-width: 70px, width: 70px, horizontal-stretch: 0 },
                                { title: "Label", min-width: 160px, width: 180px, horizontal-stretch: 1 },
                            ];
                            current-row-changed(row) => { root.select_utxo(row); }
                        }
                        HorizontalLayout {
                            spacing: 8px;
                            Button { text: "Add Previous Output"; clicked => { root.add_utxo(); } }
                            Button { text: "Remove Previous Output"; clicked => { root.remove_utxo(); } }
                        }
                    }
                    if root.active_utxo_tab == 1 : StandardTableView {
                        height: 170px;
                        rows <=> root.spent_utxo_rows;
                        columns: [
                            { title: "Txid", min-width: 560px, width: 570px, horizontal-stretch: 1 },
                            { title: "Vout", min-width: 90px, width: 90px, horizontal-stretch: 0 },
                            { title: "Amount sat", min-width: 120px, width: 130px, horizontal-stretch: 0 },
                            { title: "Index", min-width: 70px, width: 70px, horizontal-stretch: 0 },
                            { title: "Label", min-width: 160px, width: 180px, horizontal-stretch: 1 },
                        ];
                    }
                }

                Text { text: "Payroll"; font-size: 20px; }
                HorizontalLayout {
                    spacing: 8px;
                    Text { text: "Txid"; width: 110px; vertical-alignment: center; }
                    LineEdit { text <=> root.txid; }
                }
                HorizontalLayout {
                    spacing: 8px;
                    Text { text: "Vout"; width: 110px; vertical-alignment: center; }
                    LineEdit { text <=> root.vout; width: 90px; }
                    Text { text: "UTXO Index"; width: 110px; vertical-alignment: center; }
                    LineEdit { text <=> root.utxo_derivation_index; width: 90px; }
                    Text { text: "Amount sat"; width: 110px; vertical-alignment: center; }
                    LineEdit { text <=> root.prevout_amount_sat; width: 170px; }
                    Text { text: "Fee sat"; width: 70px; vertical-alignment: center; }
                    LineEdit { text <=> root.miner_fee_sat; width: 130px; }
                }
                HorizontalLayout {
                    spacing: 8px;
                    Text { text: "PSBT"; width: 110px; vertical-alignment: center; }
                    LineEdit { text <=> root.psbt_path; }
                    Button { text: "Save PSBT"; clicked => { root.save_psbt(); } }
                }

                HorizontalLayout {
                    spacing: 8px;
                    Text { text: "Recipients"; font-size: 20px; vertical-alignment: center; }
                    Button {
                        text: root.show_recipients ? "Hide" : "Show";
                        clicked => { root.show_recipients = !root.show_recipients; }
                    }
                }
                if root.show_recipients : VerticalLayout {
                    spacing: 12px;
                    HorizontalLayout {
                        spacing: 8px;
                        Text { text: "File"; width: 110px; vertical-alignment: center; }
                        LineEdit { text <=> root.recipients_path; }
                        Button { text: "Load"; clicked => { root.load_recipients(); } }
                        Button { text: "Save"; clicked => { root.save_recipients(); } }
                    }
                    StandardTableView {
                        height: 170px;
                        rows <=> root.recipient_table_rows;
                        columns: [
                            { title: "Label", min-width: 160px, width: 200px, horizontal-stretch: 0 },
                            { title: "Address", min-width: 560px, width: 870px, horizontal-stretch: 1 },
                            { title: "Amount sat", min-width: 120px, width: 130px, horizontal-stretch: 0 },
                        ];
                    }
                }
            }

            if root.active_tab == 1 : VerticalLayout {
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
                    Text { text: "Last Index"; width: 100px; vertical-alignment: center; }
                    LineEdit { text <=> root.last_derivation_index; width: 90px; }
                    Text { text: "Change Index"; width: 110px; vertical-alignment: center; }
                    LineEdit { text <=> root.change_derivation_index; width: 90px; }
                }
                Text { text: "Descriptor"; }
                TextEdit { text <=> root.descriptor; height: 85px; }
                StandardTableView {
                    height: 120px;
                    rows <=> root.signer_rows;
                    columns: [
                        { title: "XFP", min-width: 90px, width: 90px, horizontal-stretch: 0 },
                        { title: "Derivation", min-width: 210px, width: 230px, horizontal-stretch: 0 },
                        { title: "Xpub", min-width: 540px, width: 540px, horizontal-stretch: 1 },
                    ];
                }
            }

            if root.active_tab == 2 : VerticalLayout {
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

                Text { text: "Pending UTXO State"; font-size: 20px; }
                HorizontalLayout {
                    spacing: 8px;
                    Text { text: "Vout"; width: 110px; vertical-alignment: center; }
                    LineEdit { text <=> root.pending_change_vout; width: 90px; }
                    Text { text: "Change Index"; width: 110px; vertical-alignment: center; }
                    LineEdit { text <=> root.pending_change_derivation_index; width: 90px; }
                    Text { text: "Amount sat"; width: 110px; vertical-alignment: center; }
                    LineEdit { text <=> root.pending_change_amount_sat; width: 170px; }
                    Text { text: "Label"; width: 70px; vertical-alignment: center; }
                    LineEdit { text <=> root.pending_change_label; width: 220px; }
                    Button { text: "Save UTXO State"; clicked => { root.save_utxo_state(); } }
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
        ui.on_load_utxos(move || set_status(&weak, load_utxos_into_ui(&weak)));
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
        ui.on_save_utxo_state(move || set_status(&weak, save_utxo_state_from_ui(&weak)));
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
    Ok("Loaded wallet".to_string())
}

fn save_wallet_from_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let wallet = wallet_from_ui(&ui)?;
    let path = default_path_for_network(
        wallet.network.as_str(),
        ui.get_wallet_path().as_str(),
        "wallet.toml",
    );
    ui.set_wallet_path(path.display().to_string().into());
    save_wallet(&path, &wallet)?;
    save_app_config(&wallet.network)?;
    let wallet = load_wallet(&path)?;
    ui.set_descriptor(wallet.descriptor.unwrap_or_default().into());
    ui.set_signer_rows(signer_rows(&wallet.signers));
    Ok("Saved wallet".to_string())
}

fn load_utxos_into_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let path = default_path_for_network(
        ui.get_wallet_network().as_str(),
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
    ui.set_utxo_derivation_index(utxo.derivation_index.to_string().into());
    ui.set_last_derivation_index(utxo.derivation_index.to_string().into());
    ui.set_change_derivation_index(utxo.derivation_index.saturating_add(1).to_string().into());
    Ok(format!("Selected UTXO row {}", row + 1))
}

fn add_utxo_from_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let path = default_path_for_network(
        ui.get_wallet_network().as_str(),
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

fn load_recipients_into_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let path = default_path_for_network(
        ui.get_wallet_network().as_str(),
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
    Ok("Loaded recipients".to_string())
}

fn save_recipients_from_ui(weak: &slint::Weak<PayrollGui>) -> Result<String> {
    let ui = weak.upgrade().context("GUI closed")?;
    let recipients = recipient_rows(ui.get_recipient_rows().as_str())?;
    let path = default_path_for_network(
        ui.get_wallet_network().as_str(),
        ui.get_recipients_path().as_str(),
        "recipients.toml",
    );
    ui.set_recipients_path(path.display().to_string().into());
    save_recipients(&path, &recipients)?;
    ui.set_recipient_table_rows(recipient_entry_table_rows(&recipients));
    Ok("Saved recipients".to_string())
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
    let recipients_path = default_path_for_network(
        wallet.network.as_str(),
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
    let result = finalize_payroll(ui.get_finalize_psbt_path().as_str())
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
    ui.set_last_derivation_index(change.derivation_index.to_string().into());
    ui.set_change_derivation_index(next_change_derivation_index.to_string().into());
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
    ui.set_last_derivation_index(change.derivation_index.to_string().into());
    ui.set_change_derivation_index(next_change_derivation_index.to_string().into());
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

const CONFIG_PATH: &str = "config.toml";

#[derive(Debug, Clone, Deserialize, Serialize)]
struct AppConfig {
    #[serde(default = "default_config_network")]
    network: String,
}

fn default_config_network() -> String {
    "testnet".to_string()
}

fn load_app_config() -> AppConfig {
    fs::read_to_string(CONFIG_PATH)
        .ok()
        .and_then(|contents| toml::from_str(&contents).ok())
        .unwrap_or_else(|| AppConfig {
            network: default_config_network(),
        })
}

fn save_app_config(network: &str) -> Result<()> {
    let config = AppConfig {
        network: network.to_string(),
    };
    fs::write(CONFIG_PATH, toml::to_string_pretty(&config)?)
        .with_context(|| format!("failed to write config {CONFIG_PATH}"))
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
        utxo.derivation_index.to_string(),
        utxo.label.clone().unwrap_or_default(),
    ]
}

fn selected_utxo(ui: &PayrollGui, row: i32) -> Result<TreasuryUtxo> {
    let path = default_path_for_network(
        ui.get_wallet_network().as_str(),
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
    if utxos
        .utxos
        .iter()
        .any(|existing| existing.derivation_index == utxo.derivation_index)
    {
        bail!(
            "derivation index {} is already recorded",
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
    let change_script = derive_treasury_script_pubkey(wallet, derivation_index)?;
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
    let change_script = derive_treasury_script_pubkey(wallet, derivation_index)?;
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

fn default_path_for_network(network: &str, current_path: &str, file_name: &str) -> PathBuf {
    let current = PathBuf::from(current_path.trim());
    let Some(directory) = default_network_directory(network) else {
        return current;
    };
    if is_default_file_path(&current, file_name) {
        return PathBuf::from(directory).join(file_name);
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

    #[test]
    fn testnet_network_uses_testnet_default_paths() {
        assert_eq!(
            default_path_for_network("bitcoin-testnet4", "wallet.toml", "wallet.toml"),
            PathBuf::from("testnet/wallet.toml")
        );
        assert_eq!(
            default_path_for_network("testnet", "recipients.toml", "recipients.toml"),
            PathBuf::from("testnet/recipients.toml")
        );
        assert_eq!(
            default_path_for_network("testnet", "output/utxos.toml", "utxos.toml"),
            PathBuf::from("testnet/utxos.toml")
        );
    }

    #[test]
    fn mainnet_network_uses_mainnet_default_paths() {
        assert_eq!(
            default_path_for_network("mainnet", "wallet.toml", "wallet.toml"),
            PathBuf::from("mainnet/wallet.toml")
        );
        assert_eq!(
            default_path_for_network("bitcoin", "recipients.toml", "recipients.toml"),
            PathBuf::from("mainnet/recipients.toml")
        );
    }

    #[test]
    fn explicit_custom_paths_are_preserved() {
        assert_eq!(
            default_path_for_network("testnet", "archive/wallet.toml", "wallet.toml"),
            PathBuf::from("archive/wallet.toml")
        );
    }

    #[test]
    fn existing_network_default_paths_can_switch_networks() {
        assert_eq!(
            default_path_for_network("mainnet", "testnet/wallet.toml", "wallet.toml"),
            PathBuf::from("mainnet/wallet.toml")
        );
    }

    #[test]
    fn selected_utxo_advances_change_derivation_index() {
        assert_eq!(next_change_derivation_index(7), 8);
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
    fn utxo_table_row_does_not_include_status() {
        let row = utxo_table_row(&TreasuryUtxo {
            txid: "txid".to_string(),
            vout: 1,
            amount_sat: 2,
            derivation_index: 3,
            status: UtxoStatus::Spent,
            label: Some("label".to_string()),
        });

        assert_eq!(row, vec!["txid", "1", "2", "3", "label"]);
    }

    #[test]
    fn app_config_parses_network() {
        let config: AppConfig = toml::from_str("network = \"mainnet\"").unwrap();
        assert_eq!(config.network, "mainnet");
    }

    #[test]
    fn app_config_defaults_to_testnet_when_empty() {
        let config: AppConfig = toml::from_str("").unwrap();
        assert_eq!(config.network, "testnet");
    }

    fn test_utxo(txid: &str, status: UtxoStatus) -> TreasuryUtxo {
        TreasuryUtxo {
            txid: txid.to_string(),
            vout: 0,
            amount_sat: 1_000,
            derivation_index: 0,
            status,
            label: None,
        }
    }
}
