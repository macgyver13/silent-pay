use std::cell::RefCell;
use std::rc::Rc;

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::Amount;
use frost_demo::protocol;
use frost_demo::session;
use frost_demo::wallet::{self, PublicWalletFile};
use psbt::Psbt;
use slint::ComponentHandle;

slint::include_modules!();

#[derive(Default)]
struct State {
    wallet: Option<PublicWalletFile>,
    initial: Option<Psbt>,
    signing: Option<Psbt>,
    signed: Option<Psbt>,
}

fn report(window: &CoordinatorWindow, result: anyhow::Result<String>) {
    window.set_status(match result {
        Ok(message) => message.into(),
        Err(error) => format!("Error: {error:#}").into(),
    });
}

fn main() -> anyhow::Result<()> {
    let window = CoordinatorWindow::new()?;
    let state = Rc::new(RefCell::new(State::default()));

    let weak = window.as_weak();
    let state_for_callback = state.clone();
    window.on_provision_wallet(move || {
        let Some(window) = weak.upgrade() else { return };
        let result = (|| {
            let directory = rfd::FileDialog::new()
                .pick_folder()
                .context("no folder selected")?;
            let (path, shares) = wallet::provision(&directory)?;
            state_for_callback.borrow_mut().wallet = Some(PublicWalletFile::load(&path)?);
            Ok(format!(
                "Wallet ready: {} ({} plaintext shares)",
                path.display(),
                shares.len()
            ))
        })();
        report(&window, result);
    });

    let weak = window.as_weak();
    let state_for_callback = state.clone();
    window.on_load_wallet(move || {
        let Some(window) = weak.upgrade() else { return };
        let result = (|| {
            let path = rfd::FileDialog::new()
                .add_filter("FROST wallet", &["json"])
                .pick_file()
                .context("no wallet selected")?;
            state_for_callback.borrow_mut().wallet = Some(PublicWalletFile::load(&path)?);
            Ok(format!("Loaded {}", path.display()))
        })();
        report(&window, result);
    });

    let weak = window.as_weak();
    let state_for_callback = state.clone();
    window.on_create_session(move || {
        let Some(window) = weak.upgrade() else { return };
        let result = (|| {
            let mut state = state_for_callback.borrow_mut();
            let wallet = state
                .wallet
                .as_ref()
                .context("load or provision a wallet first")?;
            let psbt = protocol::create_initial(wallet, 0, Amount::from_sat(90_000))?;
            let id = session::validate(&psbt)?;
            let path = rfd::FileDialog::new()
                .set_file_name("frost-initial.psbt")
                .save_file()
                .context("no output file selected")?;
            session::write(&psbt, &path)?;
            state.initial = Some(psbt);
            state.signing = None;
            state.signed = None;
            Ok(format!(
                "Initial PSBT exported; session {}",
                hex::encode(&id[..6])
            ))
        })();
        report(&window, result);
    });

    let weak = window.as_weak();
    let state_for_callback = state.clone();
    window.on_collect_round_one(move || {
        let Some(window) = weak.upgrade() else { return };
        let result = (|| {
            let files = rfd::FileDialog::new()
                .add_filter("PSBT", &["psbt"])
                .pick_files()
                .context("no contribution files selected")?;
            let contributions = files
                .iter()
                .map(session::read)
                .collect::<anyhow::Result<Vec<_>>>()?;
            let mut state = state_for_callback.borrow_mut();
            let initial = state
                .initial
                .as_ref()
                .context("create an initial PSBT first")?;
            let wallet = state
                .wallet
                .as_ref()
                .context("load the authenticated wallet first")?;
            state.signing = Some(protocol::collect_round_one(
                wallet,
                initial,
                &contributions,
            )?);
            Ok("Accepted exactly two round-one contributions; signing PSBT ready".into())
        })();
        report(&window, result);
    });

    let weak = window.as_weak();
    let state_for_callback = state.clone();
    window.on_export_signing(move || {
        let Some(window) = weak.upgrade() else { return };
        let result = (|| {
            let state = state_for_callback.borrow();
            let signing = state.signing.as_ref().context("collect round one first")?;
            let path = rfd::FileDialog::new()
                .set_file_name("frost-signing.psbt")
                .save_file()
                .context("no output file selected")?;
            session::write(signing, &path)?;
            Ok(format!("Signing PSBT exported to {}", path.display()))
        })();
        report(&window, result);
    });

    let weak = window.as_weak();
    let state_for_callback = state.clone();
    window.on_collect_round_two(move || {
        let Some(window) = weak.upgrade() else { return };
        let result = (|| {
            let files = rfd::FileDialog::new()
                .add_filter("PSBT", &["psbt"])
                .pick_files()
                .context("no contribution files selected")?;
            let contributions = files
                .iter()
                .map(session::read)
                .collect::<anyhow::Result<Vec<_>>>()?;
            let mut state = state_for_callback.borrow_mut();
            let signing = state
                .signing
                .as_ref()
                .context("export a signing PSBT first")?;
            state.signed = Some(protocol::collect_round_two(signing, &contributions)?);
            Ok("Accepted exactly two signature shares; transaction ready to finalize".into())
        })();
        report(&window, result);
    });

    let weak = window.as_weak();
    window.on_finalize_session(move || {
        let Some(window) = weak.upgrade() else { return };
        let result = (|| {
            let mut state = state.borrow_mut();
            let wallet = state
                .wallet
                .as_ref()
                .context("load the authenticated wallet first")?
                .clone();
            let signed = state.signed.as_mut().context("collect round two first")?;
            let transaction = protocol::finalize(&wallet, signed)?;
            let path = rfd::FileDialog::new()
                .set_file_name("frost-transaction.hex")
                .save_file()
                .context("no output file selected")?;
            std::fs::write(&path, serialize_hex(&transaction))?;
            Ok(format!("Final transaction exported: {}", path.display()))
        })();
        report(&window, result);
    });

    window.run()?;
    Ok(())
}

use anyhow::Context;
