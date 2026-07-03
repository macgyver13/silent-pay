use anyhow::Result;
use bitcoin::OutPoint;
use psbt::roles::ConstructorPsbtExt;
use psbt::Psbt;
use psbt_v2::v2::{Input, Output};

pub(crate) fn build_psbt(inputs: Vec<Input>, outputs: Vec<Output>) -> Result<Psbt> {
    let outpoints: Vec<OutPoint> = inputs
        .iter()
        .map(|input| OutPoint::new(input.previous_txid, input.spent_output_index))
        .collect();

    let psbt = Psbt::create_new_transaction(outputs).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let mut psbt = psbt
        .add_inputs(outpoints)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    for (slot, built) in psbt.inputs.iter_mut().zip(inputs.into_iter()) {
        slot.witness_utxo = built.witness_utxo;
        slot.sequence = built.sequence;
    }

    Ok(psbt)
}
