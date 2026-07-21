use std::cell::RefCell;
use std::env;
use std::path::PathBuf;
use std::rc::Rc;

use anyhow::Context;
use frost_demo::protocol::Companion;
use frost_demo::session;
use slint::ComponentHandle;

slint::include_modules!();

fn report(window: &CompanionWindow, result: anyhow::Result<String>) {
    window.set_status(match result {
        Ok(message) => message.into(),
        Err(error) => format!("Error: {error:#}").into(),
    });
}

fn share_argument() -> anyhow::Result<Option<PathBuf>> {
    let mut arguments = env::args_os().skip(1);
    let Some(argument) = arguments.next() else {
        return Ok(None);
    };
    if argument != "--share" {
        anyhow::bail!("usage: frost-companion [--share PATH]");
    }
    let path = arguments
        .next()
        .context("--share requires a share file path")?;
    if arguments.next().is_some() {
        anyhow::bail!("usage: frost-companion [--share PATH]");
    }
    Ok(Some(path.into()))
}

fn main() -> anyhow::Result<()> {
    let initial_share = share_argument()?;
    let window = CompanionWindow::new()?;
    let companion = Rc::new(RefCell::new(None::<Companion>));

    if let Some(path) = initial_share {
        let loaded = Companion::load(&path)?;
        let participant = loaded.participant();
        let round_one = loaded.round_one_file();
        let round_two = loaded.round_two_file();
        *companion.borrow_mut() = Some(loaded);
        window.set_identity(format!("Identity: {participant}").into());
        window.set_status(
            format!(
                "Ready: outputs will be {} and {}",
                round_one.display(),
                round_two.display()
            )
            .into(),
        );
    }

    let weak = window.as_weak();
    let state = companion.clone();
    window.on_load_share(move || {
        let Some(window) = weak.upgrade() else { return };
        let result = (|| {
            let path = rfd::FileDialog::new()
                .add_filter("FROST share", &["json"])
                .pick_file()
                .context("no share selected")?;
            let loaded = Companion::load(&path)?;
            let participant = loaded.participant();
            let round_one = loaded.round_one_file();
            let round_two = loaded.round_two_file();
            *state.borrow_mut() = Some(loaded);
            window.set_nonce_active(false);
            window.set_identity(format!("Identity: {participant}").into());
            Ok(format!(
                "Ready: participant {participant}; outputs will be {} and {}",
                round_one.display(),
                round_two.display()
            ))
        })();
        report(&window, result);
    });

    let weak = window.as_weak();
    let state = companion.clone();
    window.on_process_round_one(move || {
        let Some(window) = weak.upgrade() else { return };
        let result = (|| {
            let input = rfd::FileDialog::new()
                .add_filter("PSBT", &["psbt"])
                .pick_file()
                .context("no initial PSBT selected")?;
            let initial = session::read(input)?;
            let mut state = state.borrow_mut();
            let companion = state.as_mut().context("load a share first")?;
            let contribution = companion.round_one(&initial, &mut rand::rngs::OsRng)?;
            let output = companion.round_one_file();
            session::write(&contribution, &output)?;
            window.set_nonce_active(true);
            Ok(format!(
                "Round one exported to {}; keep this app open",
                output.display()
            ))
        })();
        report(&window, result);
    });

    let weak = window.as_weak();
    let state = companion.clone();
    window.on_process_round_two(move || {
        let Some(window) = weak.upgrade() else { return };
        let result = (|| {
            let input = rfd::FileDialog::new()
                .add_filter("PSBT", &["psbt"])
                .pick_file()
                .context("no signing PSBT selected")?;
            let signing = session::read(input)?;
            let mut state = state.borrow_mut();
            let companion = state.as_mut().context("load a share first")?;
            let contribution = companion.round_two(&signing)?;
            let output = companion.round_two_file();
            session::write(&contribution, &output)?;
            window.set_nonce_active(false);
            Ok(format!(
                "Completed; signature share exported to {}",
                output.display()
            ))
        })();
        report(&window, result);
    });

    let weak = window.as_weak();
    window.on_process_wallet_folder(move || {
        let Some(window) = weak.upgrade() else { return };
        let result = (|| {
            let mut state = companion.borrow_mut();
            let companion = state.as_mut().context("load a share first")?;
            if companion.has_active_nonce() {
                let input = companion.wallet_directory().join("frost-signing.psbt");
                let contribution = companion.round_two(&session::read(&input)?)?;
                let output = companion.round_two_file();
                session::write(&contribution, &output)?;
                window.set_nonce_active(false);
                Ok(format!("Round two exported to {}", output.display()))
            } else {
                let input = companion.wallet_directory().join("frost-initial.psbt");
                let contribution =
                    companion.round_one(&session::read(&input)?, &mut rand::rngs::OsRng)?;
                let output = companion.round_one_file();
                session::write(&contribution, &output)?;
                window.set_nonce_active(true);
                Ok(format!(
                    "Round one exported to {}; keep this app open",
                    output.display()
                ))
            }
        })();
        report(&window, result);
    });

    window.run()?;
    Ok(())
}
