_default:
  @just --list

[group('silent-pay')]
pay:
  cargo r -p silent-pay

coldcard_path := "output/"
[group('pay')]
payroll:
  cargo r --bin payroll -- --out-dir "{{coldcard_path}}pay"

[group('pay')]
finalize:
  cargo r --bin finalize -- {{coldcard_path}}final/r2-charlie.psbt

[group('pay')]
scan:
  cargo r --bin scan_recipients -- "{{coldcard_path}}final/r2-charlie.psbt"
