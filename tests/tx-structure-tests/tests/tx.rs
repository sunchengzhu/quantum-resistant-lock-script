use ckb_fips205_utils::signing::TxSigner;
use ckb_gen_types::bytes::Bytes;
use ckb_gen_types::packed::{CellInput, CellOutput, WitnessArgs};
use ckb_gen_types::prelude::{Builder, Entity, Pack};
use ckb_testtool::context::Context;
use ckb_types::core::{Capacity, TransactionBuilder, TransactionView};
use ckb_types::prelude::IntoTransactionView;
use multisig_tests::utils::signer_strategy;
use proptest::prelude::ProptestConfig;
use proptest::proptest;
use rand::{CryptoRng, RngCore, SeedableRng, rngs::StdRng};
use tx_structure_tests::Loader;
use tx_structure_tests::cells::sphincsplus_data::SphincsplusData;
use tx_structure_tests::prelude::ContextExt;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 10, .. ProptestConfig::default()
    })]

    #[test]
    fn test_sphincsplus_one_input(
        signer in signer_strategy(),
        seed: u64,
    ) {

        let mut rng = StdRng::seed_from_u64(seed);
        let pubkey_bytes = signer.public_key_bytes();


        // 用 Vec<u8> 存储公钥，动态长度
        let cell_data_struct = SphincsplusData {
            pubkey: pubkey_bytes.to_vec(),
        };
        // 你的 cell data
        let cell_data_bytes = cell_data_struct.as_bytes();
        // 初始化上下文 & 合约
        let mut context = Context::default();
        let contract_bin: Bytes = Loader::default().load_binary("c-sphincs-all-in-one-lock");
        let out_point = context.deploy_cell(contract_bin);

        let lock_script = context
            .build_script(&out_point, signer.script_args())
            .expect("script");

        // 构造 input / output cell
        let capacity = Capacity::shannons(100).pack();
        let input_cell_output = CellOutput::new_builder()
            .capacity(capacity.clone())
            .lock(lock_script.clone())
            .build();

        let output_cell_output = CellOutput::new_builder()
            .capacity(capacity.clone())
            .lock(lock_script.clone())
            .build();

        // 构造未签名交易
        let tx = build_custom_tx(
            &mut context,
            (
                input_cell_output.clone(),
                Bytes::from(cell_data_bytes.clone()),
            ),
            (
                output_cell_output.clone(),
                Bytes::from(cell_data_bytes.clone()),
            ),
        );

        // 签名
        let signed_tx = sign_custom_tx(
            &signer,
            &mut rng,
            &mut context,
            &tx,
            (input_cell_output, Bytes::from(cell_data_bytes)),
        );

        // 验证
        let ret = context.should_be_passed(&signed_tx, 1_000_000_000);
        println!("ret: {:?}", ret);
    }

    #[test]
    fn test_sphincsplus_two_inputs(
        signer in signer_strategy(),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let pubkey_bytes = signer.public_key_bytes();

        // 用 Vec<u8> 存储公钥，动态长度
        let cell_data_struct = SphincsplusData {
            pubkey: pubkey_bytes.to_vec(),
        };
        let cell_data_bytes = cell_data_struct.as_bytes();

        // 初始化上下文 & 合约
        let mut context = Context::default();
        let contract_bin: Bytes = Loader::default().load_binary("c-sphincs-all-in-one-lock");
        let out_point = context.deploy_cell(contract_bin);

        let lock_script = context
            .build_script(&out_point, signer.script_args())
            .expect("script");

        // 构造两个输入 cell
        let capacity = Capacity::shannons(100).pack();
        let input_cell_output1 = CellOutput::new_builder()
            .capacity(capacity.clone())
            .lock(lock_script.clone())
            .build();

        let input_cell_output2 = CellOutput::new_builder()
            .capacity(capacity.clone())
            .lock(lock_script.clone())
            .build();

        // 构造一个输出 cell
        let output_cell_output = CellOutput::new_builder()
            .capacity(capacity.clone())
            .lock(lock_script.clone())
            .build();

        // 调用 build_custom_tx_multi_inputs，传入两个输入（切片）和一个输出
        let tx = build_custom_tx_multi_inputs(
            &mut context,
            &[
                (input_cell_output1.clone(), Bytes::from(cell_data_bytes.clone())),
                (input_cell_output2.clone(), Bytes::from(cell_data_bytes.clone())),
            ],
            (output_cell_output.clone(), Bytes::from(cell_data_bytes.clone())),
        );

        let signed_tx = sign_custom_tx_multi_inputs(
            &signer,
            &mut rng,
            &mut context,
            &tx,
            &[
                (input_cell_output1, Bytes::from(cell_data_bytes.clone())),
                (input_cell_output2, Bytes::from(cell_data_bytes)),
            ],
        );

        // 验证
        let ret = context.should_be_passed(&signed_tx, 1_000_000_000);
        println!("ret: {:?}", ret);
    }
}

/// 构造一个未签名交易，允许传入自定义的 input/output cell
fn build_custom_tx(
    context: &mut Context,
    input_cell: (CellOutput, Bytes),
    output_cell: (CellOutput, Bytes),
) -> TransactionView {
    let input = CellInput::new_builder()
        .previous_output(context.create_cell(input_cell.0.clone(), input_cell.1.clone()))
        .build();

    TransactionBuilder::default()
        .input(input)
        .output(output_cell.0.clone())
        .output_data(output_cell.1.clone().pack())
        .witness(
            WitnessArgs::new_builder()
                .input_type(Some(Bytes::from(vec![0u8; 200])).pack())
                .output_type(Some(Bytes::from(vec![0u8; 200])).pack())
                .build()
                .as_bytes()
                .pack(),
        )
        .build()
}

fn sign_custom_tx<S, R>(
    signer: &S,
    rng: &mut R,
    context: &mut Context,
    tx: &TransactionView,
    input_cell: (CellOutput, Bytes),
) -> TransactionView
where
    S: TxSigner,
    R: CryptoRng + RngCore,
{
    let unsigned_tx = context.complete_tx(tx.clone());
    let signed_tx = signer.sign_tx(rng, &unsigned_tx.data(), &[input_cell], 0);
    signed_tx.into_view()
}

fn build_custom_tx_multi_inputs(
    context: &mut Context,
    input_cells: &[(CellOutput, Bytes)],
    output_cell: (CellOutput, Bytes),
) -> TransactionView {
    let inputs: Vec<CellInput> = input_cells
        .iter()
        .map(|(output, data)| {
            CellInput::new_builder()
                .previous_output(context.create_cell(output.clone(), data.clone()))
                .build()
        })
        .collect();

    TransactionBuilder::default()
        .set_inputs(inputs)
        .output(output_cell.0.clone())
        .output_data(output_cell.1.clone().pack())
        .witness(
            WitnessArgs::new_builder()
                .input_type(Some(Bytes::from(vec![0u8; 200])).pack())
                .output_type(Some(Bytes::from(vec![0u8; 200])).pack())
                .build()
                .as_bytes()
                .pack(),
        )
        .build()
}

fn sign_custom_tx_multi_inputs<S, R>(
    signer: &S,
    rng: &mut R,
    context: &mut Context,
    tx: &TransactionView,
    input_cells: &[(CellOutput, Bytes)],
) -> TransactionView
where
    S: TxSigner,
    R: CryptoRng + RngCore,
{
    let unsigned_tx = context.complete_tx(tx.clone());
    let signed_tx = signer.sign_tx(rng, &unsigned_tx.data(), input_cells, 0);
    signed_tx.into_view()
}
