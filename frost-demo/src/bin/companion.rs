use std::cell::RefCell;
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

fn main() -> anyhow::Result<()> {
    let window = CompanionWindow::new()?;
    let companion = Rc::new(RefCell::new(None::<Companion>));

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
            *state.borrow_mut() = Some(loaded);
            window.set_nonce_active(false);
            Ok(format!("Ready: participant {participant}"))
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
            let contribution = state
                .borrow_mut()
                .as_mut()
                .context("load a share first")?
                .round_one(&initial, &mut rand::rngs::OsRng)?;
            let output = rfd::FileDialog::new()
                .set_file_name("frost-round-one.psbt")
                .save_file()
                .context("no output file selected")?;
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
    window.on_process_round_two(move || {
        let Some(window) = weak.upgrade() else { return };
        let result = (|| {
            let input = rfd::FileDialog::new()
                .add_filter("PSBT", &["psbt"])
                .pick_file()
                .context("no signing PSBT selected")?;
            let signing = session::read(input)?;
            let contribution = companion
                .borrow_mut()
                .as_mut()
                .context("load a share first")?
                .round_two(&signing)?;
            let output = rfd::FileDialog::new()
                .set_file_name("frost-round-two.psbt")
                .save_file()
                .context("no output file selected")?;
            session::write(&contribution, &output)?;
            window.set_nonce_active(false);
            Ok(format!(
                "Completed; signature share exported to {}",
                output.display()
            ))
        })();
        report(&window, result);
    });

    window.run()?;
    Ok(())
}
