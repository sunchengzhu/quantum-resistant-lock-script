use ckb_fips205_utils::signing::TxSigner;
use ckb_gen_types::bytes::Bytes;
use ckb_gen_types::packed::{CellDep, CellInput, CellOutput, OutPoint, WitnessArgs};
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


    #[test]
    fn test_mixed_lock_inputs(
        signer in signer_strategy(),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let pubkey_bytes = signer.public_key_bytes();

        let cell_data_struct = SphincsplusData { pubkey: pubkey_bytes.to_vec() };
        let cell_data_bytes = cell_data_struct.as_bytes();

        let mut context = Context::default();

        // 部署两个合约
        let sphincs_bin: Bytes = Loader::default().load_binary("c-sphincs-all-in-one-lock");
        let sphincs_op = context.deploy_cell(sphincs_bin);
        let first_bin: Bytes = Loader::default().load_binary("first-contract");
        let first_op = context.deploy_cell(first_bin);

        // 构造两个 lock_script：inputs[0] 用 sphincs；inputs[1] 用 first
        let lock_sphincs = context.build_script(&sphincs_op, signer.script_args()).expect("sphincs");
        let lock_first   = context.build_script(&first_op, Bytes::from(vec![42])).expect("first");

        let cap = Capacity::shannons(100).pack();

        // 两个输入（注意顺序：0 = sphincs，1 = first）
        let in0_output = CellOutput::new_builder().capacity(cap.clone()).lock(lock_sphincs.clone()).build();
        let in1_output = CellOutput::new_builder().capacity(cap.clone()).lock(lock_first.clone()).build();

        // 一个输出（随意：用 sphincs 的锁）
        let out0_output = CellOutput::new_builder().capacity(cap.clone()).lock(lock_sphincs.clone()).build();

        // 构造未签名 tx（带空 witness + 两个 cell dep）
        let tx = build_tx_two_inputs_one_output(
            &mut context,
            &sphincs_op,
            &first_op,
            (in0_output.clone(), Bytes::from(cell_data_bytes.clone())), // in0 data: sphincs cell data
            (in1_output.clone(), Bytes::new()),                         // in1 data: first-contract 无数据
            (out0_output.clone(), Bytes::from(cell_data_bytes.clone())),
        );

        // all_inputs 必须覆盖整笔交易的 inputs，顺序一致
        let all_inputs = vec![
            (in0_output.clone(), Bytes::from(cell_data_bytes.clone())), // index 0
            (in1_output.clone(), Bytes::new()),                         // index 1
        ];

        // 只签第 0 组（sphincs 在 inputs[0]）
        let signed_tx = sign_only_group(
            &signer,
            &mut rng,
            &mut context,
            &tx,
            &all_inputs,
            0,
        );

        // // 可视化检查 witness 顺序
        // for (i, w) in signed_tx.witnesses().into_iter().enumerate() {
        //     println!("Witness[{}] len={}", i, w.raw_data().len());
        // }

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

fn empty_witness() -> Bytes {
    WitnessArgs::new_builder().build().as_bytes()
}

/// 2 inputs (0: sphincs, 1: first), 1 output
fn build_tx_two_inputs_one_output(
    context: &mut Context,
    // 合约 out_point
    sphincs_op: &OutPoint,
    first_op: &OutPoint,
    // 两个 input 的 (CellOutput, Data)
    in0: (CellOutput, Bytes),
    in1: (CellOutput, Bytes),
    // 一个 output
    out0: (CellOutput, Bytes),
) -> TransactionView {
    // 先在 context 里创建前态 cells，然后拿到 OutPoint 组装 inputs
    let prev0 = context.create_cell(in0.0.clone(), in0.1.clone());
    let prev1 = context.create_cell(in1.0.clone(), in1.1.clone());
    let input0 = CellInput::new_builder().previous_output(prev0).build();
    let input1 = CellInput::new_builder().previous_output(prev1).build();

    // 显式加上两个合约的 cell_dep（有些环境 complete_tx 会补，但我们手动加以排除干扰）
    let dep_sphincs = CellDep::new_builder().out_point(sphincs_op.clone()).build();
    let dep_first = CellDep::new_builder().out_point(first_op.clone()).build();

    // 给每个 input 先放一个“空 witness 占位”，避免签名前后消息不一致
    let w0 = empty_witness();
    let w1 = empty_witness();

    TransactionBuilder::default()
        .cell_dep(dep_sphincs)
        .cell_dep(dep_first)
        .input(input0)
        .input(input1)
        .output(out0.0.clone())
        .output_data(out0.1.clone().pack())
        .witness(w0.pack())
        .witness(w1.pack())
        .build()
}

/// 只签某个脚本组，但必须传入“整笔交易的 all_inputs”
fn sign_only_group<S, R>(
    signer: &S,
    rng: &mut R,
    context: &mut Context,
    tx: &TransactionView,
    all_inputs: &[(CellOutput, Bytes)], // len 必须 == tx.inputs().len()
    first_script_group_index: usize,    // 这里我们会传 0（sphincs 在 inputs[0]）
) -> TransactionView
where
    S: TxSigner,
    R: CryptoRng + RngCore,
{
    let unsigned_tx = context.complete_tx(tx.clone());
    let signed_tx = signer.sign_tx(
        rng,
        &unsigned_tx.data(),
        all_inputs,
        first_script_group_index,
    );
    signed_tx.into_view()
}

// ================= 示例调用 =================
