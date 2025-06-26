pub mod dummy_data_loader;
pub mod utils;

use ckb_mock_tx_types::{MockCellDep, MockInfo, MockInput, MockTransaction, ReprMockTransaction};
use ckb_traits::{CellDataProvider, HeaderProvider};
use ckb_types::core::cell::ResolvedTransaction;

fn build_mock_transaction<DL: CellDataProvider + HeaderProvider>(
    rtx: &ResolvedTransaction,
    dl: &DL,
) -> Result<MockTransaction, String> {
    // For system script tests, dep group is never used. A more general
    // utility should process dep groups as well.
    assert!(rtx.resolved_dep_groups.is_empty());

    fn c<O, N>(old: &O) -> N
    where
        O: ckb_types::prelude::Entity,
        N: ckb_types_200::prelude::Entity,
    {
        N::from_slice(old.as_slice()).expect("parsing")
    }

    let mut inputs = Vec::with_capacity(rtx.resolved_inputs.len());
    for (i, input) in rtx.resolved_inputs.iter().enumerate() {
        inputs.push(MockInput {
            input: c(&rtx
                .transaction
                .inputs()
                .get(i)
                .ok_or_else(|| format!("Cannot locate cell input {} in transaction", i))?),
            output: c(&input.cell_output),
            data: input
                .mem_cell_data
                .clone()
                .or_else(|| dl.get_cell_data(&input.out_point))
                .unwrap(),
            header: input
                .transaction_info
                .clone()
                .map(|info| info.block_hash)
                .map(|h| c(&h)),
        });
    }
    let mut cell_deps = Vec::with_capacity(rtx.resolved_cell_deps.len());
    for (i, dep) in rtx.resolved_cell_deps.iter().enumerate() {
        cell_deps.push(MockCellDep {
            cell_dep: c(&rtx.transaction.cell_deps().get(i).ok_or_else(|| {
                format!(
                    "Cannot locate cell dep {}, maybe you are using a dep group?",
                    i
                )
            })?),
            output: c(&dep.cell_output),
            data: dep
                .mem_cell_data
                .clone()
                .or_else(|| dl.get_cell_data(&dep.out_point))
                .unwrap(),
            header: dep
                .transaction_info
                .clone()
                .map(|info| info.block_hash)
                .map(|h| c(&h)),
        });
    }
    let mut header_deps = Vec::with_capacity(rtx.transaction.header_deps().len());
    for header_hash in rtx.transaction.header_deps_iter() {
        let old_header = dl
            .get_header(&header_hash)
            .ok_or_else(|| format!("Cannot find header {:x}!", header_hash))?;
        let new_header: ckb_types_200::packed::Header = c(&old_header.data());

        use ckb_types_200::prelude::IntoHeaderView;
        header_deps.push(new_header.into_view());
    }
    Ok(MockTransaction {
        mock_info: MockInfo {
            inputs,
            cell_deps,
            header_deps,
            extensions: Vec::new(),
        },
        tx: c(&rtx.transaction.data()),
    })
}

pub fn save_tx<DL: CellDataProvider + HeaderProvider>(
    rtx: &ResolvedTransaction,
    dl: &DL,
    prefix: &str,
) {
    if let Some(path) = std::env::var_os("DUMP_TXS_PATH") {
        let mock_tx = build_mock_transaction(rtx, dl).expect("build mock tx");

        let tx_hash = mock_tx.tx.calc_tx_hash();
        let repr_tx: ReprMockTransaction = mock_tx.into();
        let tx_json = serde_json::to_string_pretty(&repr_tx).expect("to json");

        let directory = std::path::Path::new(&path).join(prefix);
        std::fs::create_dir_all(&directory).expect("mkdir -p");
        let full_path = directory.join(format!("0x{:x}.json", tx_hash));
        std::fs::write(full_path, tx_json).expect("write");
    }
}
