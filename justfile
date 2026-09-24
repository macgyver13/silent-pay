_default:
  @just --list

[group('silent-pay')]
pay:
  cargo r

coldcard_path := home_directory() / "src/coldcard-firmware/testing/data"
cc_sp_out := "/tmp/cc-sp-out"

[group('demo')]
payroll:
  cargo r -p sp-demo --bin payroll -- --out-dir "{{coldcard_path}}" --recipients demo/recipients.toml

[group('demo')]
finalize:
  cargo r -p sp-demo --bin finalize -- {{cc_sp_out}}/musig2-sp-final.psbt

[group('demo')]
scan:
  cargo r -p sp-demo --bin scan_recipients -- "{{cc_sp_out}}/musig2-sp-final.psbt" --recipients demo/recipients.toml

[group('demo')]
verify:
  cargo r -p sp-demo --bin verify_receipt -- "{{cc_sp_out}}/musig2-sp-final.psbt" --address tsp1qq265v49cd8psjl36mn7mg283d7m4w0d06xswnarfnh4n8yzlls04qqkmuyvvg379t7upjac7lty56h7g2t8xa8mazdket7rac49s0qlmkczrwmus --scan-key f35d3374a543fcd665c97c5871bb23edc0b61bd20984436963613a313130a7f4

regtest_wallet := "demo/regtest-wallet.toml"
regtest_out := "/tmp/sp-round-trip"
rpc_url := "http://127.0.0.1:18443"
rpc_cookie := ""

[group('round-trip')]
fund-regtest:
  cargo r -p sp-demo --bin fund_treasury -- --wallet {{regtest_wallet}} --rpc-url {{rpc_url}} --rpc-cookie {{rpc_cookie}}

[group('round-trip')]
round1:
  cargo r -p sp-demo --bin build_round1 -- --wallet {{regtest_wallet}} --recipients demo/recipients.toml --out-dir {{regtest_out}} --rpc-url {{rpc_url}} --rpc-cookie {{rpc_cookie}}

[group('round-trip')]
broadcast:
  cargo r -p sp-demo --bin broadcast_final -- --wallet {{regtest_wallet}} --tx-hex-file {{regtest_out}}/musig2-sp-final-hex.txt --rpc-url {{rpc_url}} --rpc-cookie {{rpc_cookie}}

[group('round-trip')]
verify-onchain txid:
  cargo r -p sp-demo --bin verify_onchain -- "{{regtest_out}}/musig2-sp-final.psbt" --txid {{txid}} --recipients demo/recipients.toml --rpc-url {{rpc_url}} --rpc-cookie {{rpc_cookie}}

test:
  cargo test --workspace