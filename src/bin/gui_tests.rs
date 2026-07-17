use super::*;
use silent_pay::parse_wallet;

const TEST_WALLET_TOML: &str = r#"
network = "testnet"

[[signers]]
xfp = "0f056943"
derivation_path = "m/48h/1h/0h/3h"
xpub = "tpubDF2rnouQaaYrY6CUWTapYkeFEs3h3qrzL4M52ZGoPeU9dkarJMtrw6VF1zJRGuGuAFxYS3kXtavfAwQPTQkU5dyNYpbgxcpftrR8H3U85Ez"

[[signers]]
xfp = "6ba6cfd0"
derivation_path = "m/48h/1h/0h/3h"
xpub = "tpubDFcrvj5n7gyazzxdg9k6uvzQsoQWow1xbksr7EvKPRBgUbwCdqu2qxyTJjYFNJ7MQLfdXSJV4n8xPZGtrvwQtEbktinC4EP3k8JN2hcBtz4"
"#;

#[test]
fn full_psbt_path_saves_directly() {
    assert_eq!(
        classify_psbt_save_path("/tmp/silent-pay", "output/payroll.psbt"),
        PsbtSavePath::Direct(PathBuf::from("/tmp/silent-pay/output/payroll.psbt"))
    );
}

#[test]
fn dated_psbt_path_saves_directly() {
    assert_eq!(
        classify_psbt_save_path("/tmp/silent-pay", "output/payroll-20260714.psbt"),
        PsbtSavePath::Direct(PathBuf::from(
            "/tmp/silent-pay/output/payroll-20260714.psbt"
        ))
    );
}

#[test]
fn dated_payroll_psbt_file_name_uses_yyyymmdd() {
    assert_eq!(
        dated_payroll_psbt_file_name(NaiveDate::from_ymd_opt(2026, 7, 14).unwrap()),
        "payroll-20260714.psbt"
    );
}

#[test]
fn dated_payroll_change_label_uses_yyyymmdd() {
    assert_eq!(
        dated_payroll_change_label(NaiveDate::from_ymd_opt(2026, 7, 14).unwrap()),
        "payroll 20260714 change"
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
    let mut wallet = parse_wallet(TEST_WALLET_TOML).unwrap();
    wallet.last_derivation_index = 5;
    let address_5 = receive_address(&wallet).unwrap();
    wallet.last_derivation_index = 6;
    let address_6 = receive_address(&wallet).unwrap();

    assert!(address_5.starts_with("tb1p"));
    assert!(address_6.starts_with("tb1p"));
    assert_ne!(address_5, address_6);
}

#[test]
fn change_address_changes_with_change_derivation_index() {
    let mut wallet = parse_wallet(TEST_WALLET_TOML).unwrap();
    wallet.change_derivation_index = 5;
    let address_5 = change_address(&wallet).unwrap();
    wallet.change_derivation_index = 6;
    let address_6 = change_address(&wallet).unwrap();

    assert!(address_5.starts_with("tb1p"));
    assert!(address_6.starts_with("tb1p"));
    assert_ne!(address_5, address_6);
}

#[test]
fn change_prevout_from_tx_allows_no_change_output() {
    let wallet = parse_wallet(TEST_WALLET_TOML).unwrap();
    let tx = test_tx(vec![bitcoin::TxOut {
        value: Amount::from_sat(2_000),
        script_pubkey: bitcoin::ScriptBuf::new(),
    }]);

    let change = change_prevout_from_tx(&tx, "change-txid", &wallet, 0).unwrap();

    assert!(change.is_none());
}

#[test]
fn change_prevout_from_tx_detects_single_change_output() {
    let wallet = parse_wallet(TEST_WALLET_TOML).unwrap();
    let change_script = derive_treasury_script_pubkey(&wallet, CHANGE_CHAIN, 0).unwrap();
    let tx = test_tx(vec![bitcoin::TxOut {
        value: Amount::from_sat(2_000),
        script_pubkey: change_script,
    }]);

    let change = change_prevout_from_tx(&tx, "change-txid", &wallet, 0)
        .unwrap()
        .expect("change");

    assert_eq!(change.txid, "change-txid");
    assert_eq!(change.vout, 0);
    assert_eq!(change.amount_sat, 2_000);
    assert_eq!(change.derivation_index, 0);
}

#[test]
fn change_prevout_from_tx_rejects_multiple_change_outputs() {
    let wallet = parse_wallet(TEST_WALLET_TOML).unwrap();
    let change_script = derive_treasury_script_pubkey(&wallet, CHANGE_CHAIN, 0).unwrap();
    let tx = test_tx(vec![
        bitcoin::TxOut {
            value: Amount::from_sat(2_000),
            script_pubkey: change_script.clone(),
        },
        bitcoin::TxOut {
            value: Amount::from_sat(3_000),
            script_pubkey: change_script,
        },
    ]);

    let err = change_prevout_from_tx(&tx, "change-txid", &wallet, 0).unwrap_err();

    assert_eq!(
        err.to_string(),
        "expected at most one output matching change derivation index 0, found 2"
    );
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

    assert_eq!(row, vec!["txid", "1", "0", "3", "2", "label"]);
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
fn append_scanned_utxo_skips_duplicate_outpoint() {
    let mut utxos = UtxoFile { utxos: Vec::new() };
    let utxo = |txid: &str, vout: u32| TreasuryUtxo {
        txid: txid.to_string(),
        vout,
        amount_sat: 1_000,
        chain: RECEIVE_CHAIN,
        derivation_index: 0,
        status: UtxoStatus::Available,
        label: None,
    };
    assert!(append_scanned_utxo(&mut utxos, utxo("aa", 0)));
    // Same txid:vout is skipped, not an error.
    assert!(!append_scanned_utxo(&mut utxos, utxo("aa", 0)));
    // Different vout is a distinct output and is added.
    assert!(append_scanned_utxo(&mut utxos, utxo("aa", 1)));
    assert_eq!(utxos.utxos.len(), 2);
}

#[test]
fn scan_floor_is_lowest_unspent_index_per_chain() {
    let utxo = |chain: u32, index: u32, status: UtxoStatus| TreasuryUtxo {
        txid: format!("{chain}-{index}"),
        vout: 0,
        amount_sat: 1_000,
        chain,
        derivation_index: index,
        status,
        label: None,
    };
    let utxos = UtxoFile {
        utxos: vec![
            // Receive chain: 0-2 spent, 3 and 5 available -> floor 3.
            utxo(RECEIVE_CHAIN, 0, UtxoStatus::Spent),
            utxo(RECEIVE_CHAIN, 1, UtxoStatus::Spent),
            utxo(RECEIVE_CHAIN, 2, UtxoStatus::Spent),
            utxo(RECEIVE_CHAIN, 5, UtxoStatus::Available),
            utxo(RECEIVE_CHAIN, 3, UtxoStatus::Available),
            // Change chain: available at 0 -> floor 0.
            utxo(CHANGE_CHAIN, 0, UtxoStatus::Available),
        ],
    };
    assert_eq!(scan_floor(&utxos, RECEIVE_CHAIN), 3);
    assert_eq!(scan_floor(&utxos, CHANGE_CHAIN), 0);
}

#[test]
fn scan_floor_defaults_to_zero_without_unspent_records() {
    let spent = TreasuryUtxo {
        txid: "aa".to_string(),
        vout: 0,
        amount_sat: 1_000,
        chain: RECEIVE_CHAIN,
        derivation_index: 4,
        status: UtxoStatus::Spent,
        label: None,
    };
    // Empty chain -> 0.
    assert_eq!(
        scan_floor(&UtxoFile { utxos: Vec::new() }, RECEIVE_CHAIN),
        0
    );
    // All spent -> 0 (full scan; floor self-advances only while unspent exist).
    assert_eq!(
        scan_floor(&UtxoFile { utxos: vec![spent] }, RECEIVE_CHAIN),
        0
    );
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

fn test_tx(output: Vec<bitcoin::TxOut>) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::null(),
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output,
    }
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
            address: "tb1recipient1".to_string(),
            amount_sat: 1_000,
        },
        RecipientEntry {
            label: Some("second".to_string()),
            address: "tb1recipient2".to_string(),
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
