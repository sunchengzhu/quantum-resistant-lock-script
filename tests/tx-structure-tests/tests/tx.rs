use ckb_fips205_utils::signing::{Sha2128F, TxSigner};
use ckb_gen_types::packed::{BytesOpt, WitnessArgs};
use ckb_gen_types::prelude::{Builder, Entity, Pack};
use rand::{SeedableRng, rngs::StdRng};
use tx_structure_tests::ContractUtil;
use tx_structure_tests::cells::sphincsplus_data::{
    SPHINCSPLUS_PK_SIZE, SphincsplusData, SphincsplusDataCell,
};
use tx_structure_tests::prelude::ContextExt;

#[test]
fn test_sphincsplus_transfer_successful() {
    // 1. 初始化随机数与 signer
    let mut rng = StdRng::seed_from_u64(42);
    let signer = Sha2128F::new(&mut rng);

    // 2. 构造 cell data
    let pubkey_bytes = signer.public_key_bytes();
    let mut pubkey_arr = vec![0u8; pubkey_bytes.len()];
    pubkey_arr.copy_from_slice(&pubkey_bytes);
    let pubkey_vec = signer.public_key_bytes();
    assert_eq!(pubkey_vec.len(), 32); // 防御性检查
    let pubkey_arr: [u8; 32] = signer
        .public_key_bytes()
        .as_ref()
        .try_into()
        .expect("pk length should be 32");
    let cell_data = SphincsplusData { pubkey: pubkey_arr };
    let input_cell = SphincsplusDataCell::new([0u8; 32], cell_data);

    // 3. 组装 lock 字节（严格遵守多签合约格式）
    let mut lock_bytes = Vec::new();
    lock_bytes.push(0x00); // reserved
    lock_bytes.push(0x01); // require_first_n
    lock_bytes.push(0x01); // threshold
    lock_bytes.push(0x01); // pubkeys

    // flag: 0x80 | param_id(=0)（假如是 Sha2128F），具体按你的合约参数
    let flag = 0x80; // 最高位表示有签名，param_id=0（单签合约一般是0）
    lock_bytes.push(flag);

    // pubkey
    lock_bytes.extend_from_slice(&pubkey_bytes[..SPHINCSPLUS_PK_SIZE]);

    // message 按合约计算，通常是 blake2b 哈希/原文
    let message = b"ckb test message";

    // 签名
    let signature = signer.sign_message(&mut rng, message);
    lock_bytes.extend_from_slice(&signature);

    // 4. 构造 WitnessArgs（lock=组装好的 lock 字节，input_type/output_type 为空）
    let witness_args = WitnessArgs::new_builder()
        .lock(BytesOpt::new_builder().set(Some(lock_bytes.pack())).build())
        .build();

    // 5. ContractUtil 流程组装 tx
    let mut ct = ContractUtil::new();
    let type_contract = ct.deploy_contract("c-sphincs-all-in-one-lock");

    // 新建空 tx
    let mut tx = ckb_testtool::ckb_types::core::TransactionBuilder::default().build();

    // 添加 input/output
    tx = ct.add_input(tx, type_contract.clone(), None, &input_cell, 100);
    tx = ct.add_outpoint(tx, type_contract.clone(), None, &input_cell, 100);

    // 6. 设置 witness
    tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![witness_args.as_bytes().pack()])
        .build();

    // 7. 完成 tx 并校验
    tx = ct.context.complete_tx(tx);
    let ret = ct.context.should_be_passed(&tx, 10_000_000);
    println!("ret: {:?}", ret);
}
