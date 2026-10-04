use std::cell::RefCell;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::rc::Rc;

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::Amount;
use frost_demo::protocol;
use frost_demo::session;
use frost_demo::wallet::{self, PublicWalletFile, Scheme};
use psbt::Psbt;
use slint::ComponentHandle;

slint::include_modules!();

#[derive(Default)]
struct State {
    wallet: Option<PublicWalletFile>,
    wallet_directory: Option<PathBuf>,
    initial: Option<Psbt>,
    signing: Option<Psbt>,
    signed: Option<Psbt>,
}

fn companion_executable() -> anyhow::Result<PathBuf> {
    let coordinator = env::current_exe().context("find coordinator executable")?;
    let companion = coordinator
        .parent()
        .context("coordinator executable has no parent folder")?
        .join(format!("frost-companion{}", env::consts::EXE_SUFFIX));
    if !companion.is_file() {
        anyhow::bail!(
            "companion executable is unavailable at {}; build it with `cargo build -p frost-demo --bin frost-companion`",
            companion.display()
        );
    }
    Ok(companion)
}

fn numbered_contributions(
    directory: &std::path::Path,
    round: &str,
) -> anyhow::Result<(Vec<Psbt>, String)> {
    let contributions = (1..=3)
        .filter_map(|participant| {
            let path = directory.join(format!("frost-{round}.{participant}.psbt"));
            path.exists().then_some((participant, path))
        })
        .map(|(participant, path)| Ok((participant, session::read(path)?)))
        .collect::<anyhow::Result<Vec<_>>>()?;
    if contributions.len() != 2 {
        anyhow::bail!(
            "expected exactly two {round} files in {}, found {}",
            directory.display(),
            contributions.len()
        );
    }
    let identities = contributions
        .iter()
        .map(|(participant, _)| participant.to_string())
        .collect::<Vec<_>>()
        .join(" and ");
    Ok((
        contributions.into_iter().map(|(_, psbt)| psbt).collect(),
        identities,
    ))
}

fn launch_companion_for(state: &State, participant: u16) -> anyhow::Result<()> {
    let directory = state
        .wallet_directory
        .as_ref()
        .context("load or provision a wallet first")?;
    let share = directory.join(format!("frost-share-{participant}.json"));
    if !share.is_file() {
        anyhow::bail!("companion share is unavailable at {}", share.display());
    }
    let companion = companion_executable()?;
    Command::new(&companion)
        .arg("--share")
        .arg(&share)
        .spawn()
        .with_context(|| format!("launch {}", companion.display()))?;
    Ok(())
}

fn clear_session_artifacts(directory: &std::path::Path) -> anyhow::Result<usize> {
    let mut removed = 0;
    for entry in fs::read_dir(directory)
        .with_context(|| format!("read wallet folder {}", directory.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if !entry.file_type()?.is_file() {
            continue;
        }
        let extension = path.extension().and_then(|extension| extension.to_str());
        if matches!(extension, Some("psbt" | "hex")) {
            fs::remove_file(&path)
                .with_context(|| format!("remove prior session artifact {}", path.display()))?;
            removed += 1;
        }
    }
    Ok(removed)
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
    window.on_provision_wallet(move |bip445| {
        let Some(window) = weak.upgrade() else { return };
        let result = (|| {
            let directory = rfd::FileDialog::new()
                .pick_folder()
                .context("no folder selected")?;
            let scheme = if bip445 {
                Scheme::Bip445
            } else {
                Scheme::Rfc9591
            };
            let (path, shares) = wallet::provision(&directory, scheme)?;
            let mut state = state_for_callback.borrow_mut();
            state.wallet = Some(PublicWalletFile::load(&path)?);
            state.wallet_directory = Some(directory);
            Ok(format!(
                "{scheme:?} wallet ready: {} ({} plaintext shares)",
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
            let directory = path
                .parent()
                .context("wallet file has no parent folder")?
                .to_owned();
            let mut state = state_for_callback.borrow_mut();
            let wallet = PublicWalletFile::load(&path)?;
            let scheme = wallet.scheme;
            state.wallet = Some(wallet);
            state.wallet_directory = Some(directory);
            Ok(format!("Loaded {scheme:?} wallet {}", path.display()))
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
            let psbt = protocol::create_initial(wallet, 5, Amount::from_sat(90_000))?;
            let path = state
                .wallet_directory
                .as_ref()
                .context("wallet folder is unavailable")?
                .join("frost-initial.psbt");
            let removed = clear_session_artifacts(
                state
                    .wallet_directory
                    .as_deref()
                    .context("wallet folder is unavailable")?,
            )?;
            session::write(&psbt, &path)?;
            state.initial = Some(psbt);
            state.signing = None;
            state.signed = None;
            Ok(format!(
                "Cleared {removed} prior PSBT/hex artifact(s); initial PSBT exported"
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
    window.on_launch_companion_one(move || {
        let Some(window) = weak.upgrade() else { return };
        let result = launch_companion_for(&state_for_callback.borrow(), 1)
            .map(|_| "Launched companion identity 1".into());
        report(&window, result);
    });

    let weak = window.as_weak();
    let state_for_callback = state.clone();
    window.on_launch_companion_two(move || {
        let Some(window) = weak.upgrade() else { return };
        let result = launch_companion_for(&state_for_callback.borrow(), 2)
            .map(|_| "Launched companion identity 2".into());
        report(&window, result);
    });

    let weak = window.as_weak();
    let state_for_callback = state.clone();
    window.on_launch_companion_three(move || {
        let Some(window) = weak.upgrade() else { return };
        let result = launch_companion_for(&state_for_callback.borrow(), 3)
            .map(|_| "Launched companion identity 3".into());
        report(&window, result);
    });

    let weak = window.as_weak();
    let state_for_callback = state.clone();
    window.on_auto_collect_round_one(move || {
        let Some(window) = weak.upgrade() else { return };
        let result = (|| {
            let mut state = state_for_callback.borrow_mut();
            let directory = state
                .wallet_directory
                .as_ref()
                .context("load or provision a wallet first")?
                .clone();
            let wallet = state
                .wallet
                .as_ref()
                .context("load the authenticated wallet first")?
                .clone();
            let initial = match state.initial.clone() {
                Some(initial) => initial,
                None => session::read(directory.join("frost-initial.psbt"))?,
            };
            let (contributions, identities) = numbered_contributions(&directory, "round-one")?;
            let signing = protocol::collect_round_one(&wallet, &initial, &contributions)?;
            let output = directory.join("frost-signing.psbt");
            session::write(&signing, &output)?;
            state.initial = Some(initial);
            state.signing = Some(signing);
            Ok(format!(
                "Collected round one from identities {identities}; exported {}",
                output.display()
            ))
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
    let state_for_callback = state.clone();
    window.on_auto_collect_round_two(move || {
        let Some(window) = weak.upgrade() else { return };
        let result = (|| {
            let mut state = state_for_callback.borrow_mut();
            let directory = state
                .wallet_directory
                .as_ref()
                .context("load or provision a wallet first")?
                .clone();
            let signing = match state.signing.clone() {
                Some(signing) => signing,
                None => session::read(directory.join("frost-signing.psbt"))?,
            };
            let (contributions, identities) = numbered_contributions(&directory, "round-two")?;
            state.signed = Some(protocol::collect_round_two(&signing, &contributions)?);
            state.signing = Some(signing);
            Ok(format!(
                "Collected round two from identities {identities}; ready to finalize"
            ))
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
            let directory = state
                .wallet_directory
                .as_ref()
                .context("wallet folder is unavailable")?
                .clone();
            let signed = state.signed.as_mut().context("collect round two first")?;
            let transaction = protocol::finalize(&wallet, signed)?;
            let finalized_psbt = directory.join("frost-finalized.psbt");
            session::write(signed, &finalized_psbt)?;
            let path = rfd::FileDialog::new()
                .set_file_name("frost-transaction.hex")
                .save_file()
                .context("no output file selected")?;
            std::fs::write(&path, serialize_hex(&transaction))?;
            Ok(format!(
                "Finalized PSBT exported to {}; transaction hex exported to {}",
                finalized_psbt.display(),
                path.display()
            ))
        })();
        report(&window, result);
    });

    window.run()?;
    Ok(())
}

use anyhow::Context;
