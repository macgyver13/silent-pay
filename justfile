_default:
  @just --list

[group('silent-pay')]
pay:
  cargo r --bin gui

coldcard_path := home_directory() / "src/coldcard-firmware/testing/data"
recipient_path := home_directory() / "work/silent_pay"
cc_sp_out := "/tmp/cc-sp-out"

[group('demo')]
payroll:
  cargo r --bin payroll -- --out-dir "{{coldcard_path}}" --recipients {{recipient_path}}/testnet/recipients.toml

[group('demo')]
finalize:
  cargo r --bin finalize -- {{cc_sp_out}}/musig2-sp-final.psbt

[group('demo')]
scan:
  cargo r --bin scan_recipients -- "{{cc_sp_out}}/musig2-sp-final.psbt" --recipients {{recipient_path}}/testnet/recipients.toml
