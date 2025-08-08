use crate::{Loader, utils::*};
use ckb_fips205_utils::{Hasher, construct_flag, signing::TxSigner};
use ckb_testtool::{
    ckb_error::Error,
    ckb_types::{
        bytes::Bytes,
        core::{Cycle, TransactionBuilder, TransactionView},
        packed::*,
        prelude::*,
    },
    context::Context,
};
use proptest::{collection::vec, prelude::*};
use rand::{Rng, SeedableRng, rngs::StdRng};
use rand_core::CryptoRngCore;
use std::cell::RefCell;

const C_NAME: &str = "c-sphincs-all-in-one-lock";
const HYBRID_NAME: &str = "hybrid-sphincs-all-in-one-lock";
const RUST_NAME: &str = "sphincs-all-in-one-lock";

proptest! {
    #[test]
    fn test_single_signer_c(
        signer in signer_strategy(),
        seed: u64,
    ) {
        let signers = [signer];
        let rng = StdRng::seed_from_u64(seed);

        let cycles = _run_valid_tx(
            C_NAME,
            &signers,
            1,
            1,
            &[0],
            rng,
        ).expect("pass verification");
        println!("consume cycles: {cycles}");
    }

    #[test]
    fn test_multi_valid_signer_c(
        signers in vec(signer_strategy(), 1..7),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = rng.gen_range(1..=signers.len());
        println!("Pubkeys: {}, threshold: {}", signers.len(), threshold);
        let selected = gen_selected(
            &mut rng,
            signers.len(),
            threshold,
            0,
        );
        println!("Selected signer indices: {selected:?}");

        let cycles = _run_valid_tx(
            C_NAME,
            &signers,
            threshold,
            0,
            &selected,
            rng,
        ).expect("pass verification");
        println!("consume cycles: {cycles}");
    }

    #[test]
    fn test_multi_valid_signer_first_n_c(
        signers in vec(signer_strategy(), 1..7),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = rng.gen_range(1..=signers.len());
        let first_n = rng.gen_range(1..=threshold);
        println!("Pubkeys: {}, threshold: {}, require_first_n: {}",
            signers.len(), threshold, first_n);
        let selected = gen_selected(
            &mut rng,
            signers.len(),
            threshold,
            first_n,
        );
        println!("Selected signer indices: {selected:?}");

        let cycles = _run_valid_tx(
            C_NAME,
            &signers,
            threshold,
            first_n,
            &selected,
            rng,
        ).expect("pass verification");
        println!("consume cycles: {cycles}");
    }

    #[test]
    fn test_single_signer_hybrid(
        signer in signer_strategy(),
        seed: u64,
    ) {
        let signers = [signer];
        let rng = StdRng::seed_from_u64(seed);

        let cycles = _run_valid_tx(
            HYBRID_NAME,
            &signers,
            1,
            1,
            &[0],
            rng,
        ).expect("pass verification");
        println!("consume cycles: {cycles}");
    }

    #[test]
    fn test_multi_valid_signer_hybrid(
        signers in vec(signer_strategy(), 1..7),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = rng.gen_range(1..=signers.len());
        println!("Pubkeys: {}, threshold: {}", signers.len(), threshold);
        let selected = gen_selected(
            &mut rng,
            signers.len(),
            threshold,
            0,
        );
        println!("Selected signer indices: {selected:?}");

        let cycles = _run_valid_tx(
            HYBRID_NAME,
            &signers,
            threshold,
            0,
            &selected,
            rng,
        ).expect("pass verification");
        println!("consume cycles: {cycles}");
    }

    #[test]
    fn test_multi_valid_signer_first_n_hybrid(
        signers in vec(signer_strategy(), 1..7),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = rng.gen_range(1..=signers.len());
        let first_n = rng.gen_range(1..=threshold);
        println!("Pubkeys: {}, threshold: {}, require_first_n: {}",
            signers.len(), threshold, first_n);
        let selected = gen_selected(
            &mut rng,
            signers.len(),
            threshold,
            first_n,
        );
        println!("Selected signer indices: {selected:?}");

        let cycles = _run_valid_tx(
            HYBRID_NAME,
            &signers,
            threshold,
            first_n,
            &selected,
            rng,
        ).expect("pass verification");
        println!("consume cycles: {cycles}");
    }

    #[test]
    fn test_single_signer_rust(
        signer in signer_strategy(),
        seed: u64,
    ) {
        let signers = [signer];
        let rng = StdRng::seed_from_u64(seed);

        let cycles = _run_valid_tx(
            RUST_NAME,
            &signers,
            1,
            1,
            &[0],
            rng,
        ).expect("pass verification");
        println!("consume cycles: {cycles}");
    }

    #[test]
    fn test_multi_valid_signer_rust(
        signers in vec(signer_strategy(), 1..7),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = rng.gen_range(1..=signers.len());
        println!("Pubkeys: {}, threshold: {}", signers.len(), threshold);
        let selected = gen_selected(
            &mut rng,
            signers.len(),
            threshold,
            0,
        );
        println!("Selected signer indices: {selected:?}");

        let cycles = _run_valid_tx(
            RUST_NAME,
            &signers,
            threshold,
            0,
            &selected,
            rng,
        ).expect("pass verification");
        println!("consume cycles: {cycles}");
    }

    #[test]
    fn test_multi_valid_signer_first_n_rust(
        signers in vec(signer_strategy(), 1..7),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = rng.gen_range(1..=signers.len());
        let first_n = rng.gen_range(1..=threshold);
        println!("Pubkeys: {}, threshold: {}, require_first_n: {}",
            signers.len(), threshold, first_n);
        let selected = gen_selected(
            &mut rng,
            signers.len(),
            threshold,
            first_n,
        );
        println!("Selected signer indices: {selected:?}");

        let cycles = _run_valid_tx(
            RUST_NAME,
            &signers,
            threshold,
            first_n,
            &selected,
            rng,
        ).expect("pass verification");
        println!("consume cycles: {cycles}");
    }

    #[test]
    fn test_multi_valid_signer_order_irrelevant_c(
        signers in vec(signer_strategy(), 2..7),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = rng.gen_range(2..=signers.len());
        println!("Pubkeys: {}, threshold: {}", signers.len(), threshold);
        let mut selected = gen_selected(
            &mut rng,
            signers.len(),
            threshold,
            0,
        );
        println!("Selected signer indices: {selected:?}");
        selected.reverse();
        println!("Reversed selected signer indices: {selected:?}");

        let cycles = _run_valid_tx(
            C_NAME,
            &signers,
            threshold,
            0,
            &selected,
            rng,
        ).expect("pass verification");
        println!("consume cycles: {cycles}");
    }
}

proptest! {
    #[test]
    fn test_multi_fewer_signer_c(
        signers in vec(signer_strategy(), 1..7),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = rng.gen_range(1..=signers.len());
        let first_n = rng.gen_range(1..=threshold);
        println!("Pubkeys: {}, threshold: {}, require_first_n: {}",
            signers.len(), threshold, first_n);
        let selected = gen_selected(
            &mut rng,
            signers.len(),
            threshold - 1,
            0,
        );
        println!("Selected signer indices: {selected:?}");

        let e = _run_valid_tx(
            C_NAME,
            &signers,
            threshold,
            first_n,
            &selected,
            rng,
        ).unwrap_err();
        assert!(!format!("{e}").contains("ExceededMaximumCycles"));
    }

    #[test]
    fn test_multi_fewer_signer_hybrid(
        signers in vec(signer_strategy(), 1..7),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = rng.gen_range(1..=signers.len());
        let first_n = rng.gen_range(1..=threshold);
        println!("Pubkeys: {}, threshold: {}, require_first_n: {}",
            signers.len(), threshold, first_n);
        let selected = gen_selected(
            &mut rng,
            signers.len(),
            threshold - 1,
            0,
        );
        println!("Selected signer indices: {selected:?}");

        let e = _run_valid_tx(
            HYBRID_NAME,
            &signers,
            threshold,
            first_n,
            &selected,
            rng,
        ).unwrap_err();
        assert!(!format!("{e}").contains("ExceededMaximumCycles"));
    }

    #[test]
    fn test_multi_fewer_signer_rust(
        signers in vec(signer_strategy(), 1..7),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = rng.gen_range(1..=signers.len());
        let first_n = rng.gen_range(1..=threshold);
        println!("Pubkeys: {}, threshold: {}, require_first_n: {}",
            signers.len(), threshold, first_n);
        let selected = gen_selected(
            &mut rng,
            signers.len(),
            threshold - 1,
            0,
        );
        println!("Selected signer indices: {selected:?}");

        let e = _run_valid_tx(
            RUST_NAME,
            &signers,
            threshold,
            first_n,
            &selected,
            rng,
        ).unwrap_err();
        assert!(!format!("{e}").contains("ExceededMaximumCycles"));
    }

    #[test]
    fn test_multi_fewer_first_n_signer_c(
        signers in vec(signer_strategy(), 2..7),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = rng.gen_range(1..signers.len());
        let first_n = rng.gen_range(1..=threshold);
        println!("Pubkeys: {}, threshold: {}, require_first_n: {}",
            signers.len(), threshold, first_n);
        let selected = gen_selected_full(
            &mut rng,
            signers.len(),
            threshold,
            first_n,
            threshold,
            first_n - 1,
        );
        println!("Selected signer indices: {selected:?}");

        let e = _run_valid_tx(
            C_NAME,
            &signers,
            threshold,
            first_n,
            &selected,
            rng,
        ).unwrap_err();
        assert!(!format!("{e}").contains("ExceededMaximumCycles"));
    }

    #[test]
    fn test_multi_fewer_first_n_signer_hybrid(
        signers in vec(signer_strategy(), 2..7),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = rng.gen_range(1..signers.len());
        let first_n = rng.gen_range(1..=threshold);
        println!("Pubkeys: {}, threshold: {}, require_first_n: {}",
            signers.len(), threshold, first_n);
        let selected = gen_selected_full(
            &mut rng,
            signers.len(),
            threshold,
            first_n,
            threshold,
            first_n - 1,
        );
        println!("Selected signer indices: {selected:?}");

        let e = _run_valid_tx(
            HYBRID_NAME,
            &signers,
            threshold,
            first_n,
            &selected,
            rng,
        ).unwrap_err();
        assert!(!format!("{e}").contains("ExceededMaximumCycles"));
    }

    #[test]
    fn test_multi_fewer_first_n_signer_rust(
        signers in vec(signer_strategy(), 2..7),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = rng.gen_range(1..signers.len());
        let first_n = rng.gen_range(1..=threshold);
        println!("Pubkeys: {}, threshold: {}, require_first_n: {}",
            signers.len(), threshold, first_n);
        let selected = gen_selected_full(
            &mut rng,
            signers.len(),
            threshold,
            first_n,
            threshold,
            first_n - 1,
        );
        println!("Selected signer indices: {selected:?}");

        let e = _run_valid_tx(
            RUST_NAME,
            &signers,
            threshold,
            first_n,
            &selected,
            rng,
        ).unwrap_err();
        assert!(!format!("{e}").contains("ExceededMaximumCycles"));
    }

    #[test]
    fn test_multi_first_n_gt_threshold_c(
        signers in vec(signer_strategy(), 2..7),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        // threshold < signers.len()
        let threshold = rng.gen_range(1..=signers.len());
        let first_n = threshold + 1;
        println!("Pubkeys: {}, threshold: {}, require_first_n: {}",
            signers.len(), threshold, first_n);
        let selected = gen_selected(
            &mut rng,
            signers.len(),
            threshold - 1,
            0,
        );
        println!("Selected signer indices: {selected:?}");

        let e = _run_valid_tx(
            C_NAME,
            &signers,
            threshold,
            first_n,
            &selected,
            rng,
        ).unwrap_err();
        assert!(!format!("{e}").contains("ExceededMaximumCycles"));
        // println!("{e}");
    }

    #[test]
    fn test_multi_invalid_param_flag_lowbit_c(
        signers in vec(signer_strategy(), 1..7),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = rng.gen_range(1..=signers.len());
        let first_n = rng.gen_range(1..=threshold);
        println!("Pubkeys: {}, threshold: {}, require_first_n: {}",
            signers.len(), threshold, first_n);

        let conf = build_multisig_configuration(&signers, threshold, first_n);
        let param_flag_offset = 4;
        // Bytes -> Vec<u8>
        let mut conf_vec = conf.to_vec();
        conf_vec[param_flag_offset] |= 1;
        // println!("after patch, lock bytes: {:?}", &conf_vec[..10]);
        let conf = Bytes::from(conf_vec);

        let (context, unsigned_tx, inputs, first_script_group_index) =
            _build_unsigned_tx(C_NAME, conf, &mut rng);
        let signed_tx = _sign_multisig_tx(
            &unsigned_tx,
            &inputs,
            first_script_group_index,
            &signers,
            &(0..threshold).collect::<Vec<_>>(),
            &mut rng,
        );

        let e = context.verify_tx(&signed_tx, 1_000_000_000).unwrap_err();
        assert!(!format!("{e}").contains("ExceededMaximumCycles"));
        // println!("{e}");
    }

        #[test]
        fn test_override_fips205_s(
            signer in signer_strategy(),
            seed: u64,
        ) {
            let signers = [signer];
            let rng = StdRng::seed_from_u64(seed);

            let e = _run_valid_tx_with_fips205_s(
                C_NAME,
                &signers,
                1,      // M
                1,      // R
                &[0],   // S(签名数量)这里与“保留字段 S”无关
                rng,
                0x50,   // <- 要测试的保留字段值
            ).unwrap_err();

            assert!(!format!("{e}").contains("ExceededMaximumCycles"));
            // println!("{e}");
        }

        #[test]
        fn test_override_param_id(
            signer in signer_strategy(),
            seed: u64,
        ) {
            let signers = [signer];
            let rng = StdRng::seed_from_u64(seed);
            set_param_id_raw_override(Some(47));
            let e = _run_valid_tx(
                C_NAME,
                &signers,
                1,
                1,
                &[0],
                rng,
            ).unwrap_err();

            set_param_id_raw_override(None);
            assert!(!format!("{e}").contains("ExceededMaximumCycles"));
            // println!("{e}");
        }

    #[test]
    fn test_zero_n_c(
        signers in vec(signer_strategy(), 1..7),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = rng.gen_range(1..=signers.len());
        let first_n  = rng.gen_range(1..=threshold);
        println!("Pubkeys: {}, threshold: {}, require_first_n: {}",
            signers.len(), threshold, first_n);

        let selected = gen_selected(&mut rng, signers.len(), threshold, first_n);
        println!("Selected signer indices: {selected:?}");

        // —— 正常构造 + 签名（不直接用 _run_valid_tx，方便篡改 header）——
        let conf = build_multisig_configuration(&signers, threshold, first_n);
        let (context, unsigned_tx, inputs, first_script_group_index) =
            _build_unsigned_tx(C_NAME, conf, &mut rng);

        let signed_tx = _sign_multisig_tx(
            &unsigned_tx,
            &inputs,
            first_script_group_index,
            &signers,
            &selected,
            &mut rng,
        );

        // —— 关键：把 header 的 N（index 3）改为 0 ——
        let mut witnesses: Vec<_> = signed_tx.witnesses().into_iter().collect();
        let wraw = witnesses[first_script_group_index].raw_data();
        let wa   = WitnessArgs::from_slice(wraw.as_ref()).expect("parse witness");
        let mut lock_bytes: Vec<u8> = wa.lock().to_opt().expect("lock").unpack();

        assert!(lock_bytes.len() >= 4, "lock header too short");
        lock_bytes[3] = 0; // N = 0

        let new_wa = wa.as_builder()
            .lock(Some(Bytes::from(lock_bytes)).pack())
            .build();
        witnesses[first_script_group_index] = new_wa.as_bytes().pack();

        let tx = signed_tx.as_advanced_builder().set_witnesses(witnesses).build();

        let e = context.verify_tx(&tx, 1_000_000_000).unwrap_err();
        assert!(!format!("{e}").contains("ExceededMaximumCycles"));
        // println!("{e}");
    }

    #[test]
    fn test_zero_m_c(
        signers in vec(signer_strategy(), 1..7),
        seed: u64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let threshold = rng.gen_range(1..=signers.len());
        let first_n  = rng.gen_range(1..=threshold);
        println!("Pubkeys: {}, threshold: {}, require_first_n: {}",
            signers.len(), threshold, first_n);

        let selected = gen_selected(&mut rng, signers.len(), threshold, first_n);
        println!("Selected signer indices: {selected:?}");

        let conf = build_multisig_configuration(&signers, threshold, first_n);
        let (context, unsigned_tx, inputs, first_script_group_index) =
            _build_unsigned_tx(C_NAME, conf, &mut rng);

        let signed_tx = _sign_multisig_tx(
            &unsigned_tx,
            &inputs,
            first_script_group_index,
            &signers,
            &selected,
            &mut rng,
        );

        // —— 关键：把 header 的 M（index 2）改为 0 ——
        let mut witnesses: Vec<_> = signed_tx.witnesses().into_iter().collect();
        let wraw = witnesses[first_script_group_index].raw_data();
        let wa   = WitnessArgs::from_slice(wraw.as_ref()).expect("parse witness");
        let mut lock_bytes: Vec<u8> = wa.lock().to_opt().expect("lock").unpack();

        assert!(lock_bytes.len() >= 4, "lock header too short");
        lock_bytes[2] = 0; // M = 0

        let new_wa = wa.as_builder()
            .lock(Some(Bytes::from(lock_bytes)).pack())
            .build();
        witnesses[first_script_group_index] = new_wa.as_bytes().pack();

        let tx = signed_tx.as_advanced_builder().set_witnesses(witnesses).build();

        let e = context.verify_tx(&tx, 1_000_000_000).unwrap_err();
        assert!(!format!("{e}").contains("ExceededMaximumCycles"));
        // println!("{e}");
    }
}

fn _run_valid_tx<R: Rng + CryptoRngCore>(
    name: &'static str,
    signers: &[Signer],
    threshold: usize,
    require_first_n: usize,
    signed_indices: &[usize],
    mut rng: R,
) -> Result<Cycle, Error> {
    let conf = build_multisig_configuration(signers, threshold, require_first_n);
    let (context, unsigned_tx, inputs, first_script_group_index) =
        _build_unsigned_tx(name, conf, &mut rng);
    let signed_tx = _sign_multisig_tx(
        &unsigned_tx,
        &inputs,
        first_script_group_index,
        signers,
        signed_indices,
        &mut rng,
    );

    if let Some(path) = std::env::var_os("DUMP_TXS_PATH") {
        if let Ok(s) = std::env::var("DUMP_PROBABILITY") {
            let prob = u16::from_str_radix(&s, 10).expect("parse dump probability");
            if prob > 256 {
                panic!("DUMP_PROBABILITY can only range from 0 to 256!");
            }
            let val = signed_tx.hash().nth0().as_slice()[0] as u16;
            if val < prob {
                let directory = std::path::Path::new(&path);
                std::fs::create_dir_all(directory).expect("mkdir -p");

                let path = directory.join(format!("0x{:x}.json", signed_tx.hash()));
                let mock_tx = context.dump_tx(&signed_tx).expect("dump failed tx");
                let json = serde_json::to_string_pretty(&mock_tx).expect("json");
                std::fs::write(path, json).expect("write");
            }
        }
    }

    context.verify_tx(&signed_tx, 1_000_000_000)
}

fn _run_valid_tx_with_fips205_s<R: Rng + CryptoRngCore>(
    name: &'static str,
    signers: &[Signer],
    threshold: usize,
    require_first_n: usize,
    signed_indices: &[usize],
    mut rng: R,
    fips205_s: u8, // 新增参数：要写入的 S
) -> Result<Cycle, Error> {
    let conf = build_multisig_configuration(signers, threshold, require_first_n);
    let (context, unsigned_tx, inputs, first_script_group_index) =
        _build_unsigned_tx(name, conf, &mut rng);

    // 正常签名
    let mut signed_tx = _sign_multisig_tx(
        &unsigned_tx,
        &inputs,
        first_script_group_index,
        signers,
        signed_indices,
        &mut rng,
    );

    // —— 直接用 first_script_group_index 当作该组的首个 witness 下标 ——
    let mut witnesses: Vec<_> = signed_tx.witnesses().into_iter().collect();
    let w = witnesses[first_script_group_index].raw_data();
    let wa = WitnessArgs::from_slice(w.as_ref()).expect("parse witness args");

    // 取 lock 字节并覆盖第 0 位（保留字段 S）
    let lock_bytes = wa
        .lock()
        .to_opt()
        .expect("expect lock in witness")
        .raw_data();
    let mut v = lock_bytes.to_vec();
    assert!(!v.is_empty(), "empty lock bytes");
    v[0] = fips205_s;

    // 仅替换 lock，保留 input_type/output_type
    let new_wa = wa.as_builder().lock(Some(Bytes::from(v)).pack()).build();
    witnesses[first_script_group_index] = new_wa.as_bytes().pack();

    // 写回交易
    signed_tx = signed_tx
        .as_advanced_builder()
        .set_witnesses(witnesses)
        .build();

    eprintln!("Reserved field (S) set to 0x{:02x}", fips205_s);

    // 校验
    context.verify_tx(&signed_tx, 1_000_000_000)
}

thread_local! {
    // 覆盖 flag 里的 param_id 原始值（u8），不经过 ParamId 枚举
    static PARAM_ID_RAW_OVERRIDE: RefCell<Option<u8>> = RefCell::new(None);
}

pub fn set_param_id_raw_override(v: Option<u8>) {
    PARAM_ID_RAW_OVERRIDE.with(|c| *c.borrow_mut() = v);
}

fn get_param_id_raw_override() -> Option<u8> {
    PARAM_ID_RAW_OVERRIDE.with(|c| *c.borrow())
}

#[inline]
fn apply_raw_param_to_flag(old_flag: u8, raw: u8) -> u8 {
    // 约定：bit0 = 已签位，其余7位 = param_id
    let signed_bit = old_flag & 1;
    let pid_bits = (raw & 0x7F) << 1;
    pid_bits | signed_bit
}

fn _sign_multisig_tx<R: Rng + CryptoRngCore>(
    tx: &TransactionView,
    inputs: &[(CellOutput, Bytes)],
    first_script_group_index: usize,
    signers: &[Signer],
    sign_indices: &[usize],
    rng: &mut R,
) -> TransactionView {
    let mut lock: Vec<u8> = vec![];
    let pid_raw = get_param_id_raw_override(); // Option<u8>

    for (i, signer) in signers.iter().enumerate() {
        if sign_indices.contains(&i) {
            // Sign the transaction, then extract signature
            let single_signed_tx =
                signer.sign_tx(rng, &tx.data(), inputs, first_script_group_index);
            let first_witness = single_signed_tx
                .witnesses()
                .get(first_script_group_index)
                .unwrap();
            let witness_args =
                WitnessArgs::from_slice(&first_witness.raw_data()).expect("parse witness args");
            let single_lock: Bytes = witness_args.lock().to_opt().unwrap().unpack();

            let mut owned = single_lock.to_vec();
            if let Some(raw) = pid_raw {
                if owned.len() >= 5 {
                    owned[4] = apply_raw_param_to_flag(owned[4], raw);
                }
            }
            lock.extend(&owned[4..]);
        } else {
            // Only append param Id & public key
            let mut flag = construct_flag(signer.param_id(), false);
            if let Some(raw) = pid_raw {
                flag = apply_raw_param_to_flag(flag, raw);
            }
            lock.push(flag);
            lock.extend(&signer.public_key_bytes());
        }
    }

    // Append lock to current tx
    let mut witnesses: Vec<_> = tx.witnesses().into_iter().collect();
    let witness_args = WitnessArgs::from_slice(&witnesses[first_script_group_index].raw_data())
        .expect("parse witness args");
    let mut current_lock: Vec<u8> = witness_args.lock().to_opt().unwrap().unpack();
    current_lock.extend(&lock);
    let witness_args = witness_args
        .as_builder()
        .lock(Some(Bytes::from(current_lock)).pack())
        .build();
    witnesses[first_script_group_index] = witness_args.as_bytes().pack();

    tx.as_advanced_builder().set_witnesses(witnesses).build()
}

fn _build_unsigned_tx<R: Rng + CryptoRngCore>(
    name: &'static str,
    multisig_configuration: Bytes,
    mut rng: R,
) -> (Context, TransactionView, Vec<(CellOutput, Bytes)>, usize) {
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary(name);

    let out_point = context.deploy_cell(contract_bin);

    let mut hasher = Hasher::script_args_hasher();
    hasher.update(&multisig_configuration);
    let script_args = hasher.hash().to_vec().into();

    let lock_script = context
        .build_script(&out_point, script_args)
        .expect("script");

    let input_cell_data = gen_data(&mut rng, 1, 1000);
    let input_cell_output = CellOutput::new_builder()
        .capacity((2000u64 * 100000000u64).pack())
        .lock(lock_script.clone())
        .build();
    let input_out_point = context.create_cell(input_cell_output.clone(), input_cell_data.clone());
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();

    let output_cell_data = gen_data(&mut rng, 1, 500);
    let output_cell_output = CellOutput::new_builder()
        .capacity((1999u64 * 100000000u64).pack())
        .lock(lock_script.clone())
        .build();

    let witness_args = WitnessArgs::new_builder()
        .lock(Some(multisig_configuration.slice(0..4)).pack())
        .input_type(Some(gen_data(&mut rng, 1, 50)).pack())
        .output_type(Some(gen_data(&mut rng, 1, 50)).pack())
        .build();

    let tx = TransactionBuilder::default()
        .input(input)
        .output(output_cell_output)
        .output_data(output_cell_data.pack())
        .witness(witness_args.as_bytes().pack())
        .build();
    let unsigned_tx = context.complete_tx(tx);

    (
        context,
        unsigned_tx,
        vec![(input_cell_output, input_cell_data)],
        0,
    )
}

fn gen_data<R: Rng>(rng: &mut R, min: usize, max: usize) -> Bytes {
    let len = rng.gen_range(min..=max);
    let mut data = vec![0; len];
    rng.fill(&mut data[..]);
    data.into()
}

fn gen_selected<R: Rng>(
    rng: &mut R,
    pubkeys: usize,
    threshold: usize,
    first_n: usize,
) -> Vec<usize> {
    gen_selected_full(rng, pubkeys, threshold, first_n, threshold, first_n)
}

fn gen_selected_full<R: Rng>(
    rng: &mut R,
    pubkeys: usize,
    threshold: usize,
    first_n: usize,
    pick_threshold: usize,
    pick_first_n: usize,
) -> Vec<usize> {
    assert!(threshold <= pubkeys);
    assert!(first_n <= pubkeys);
    assert!(first_n <= threshold);
    assert!(pick_first_n <= pick_threshold);
    assert!(pick_first_n <= first_n);
    assert!(pick_threshold <= threshold);
    assert!(pubkeys - first_n >= pick_threshold - pick_first_n);

    let mut res = vec![];
    if pick_first_n > 0 {
        res.extend(rand::seq::index::sample(rng, first_n, pick_first_n));
    }
    if pick_threshold > pick_first_n {
        let additional =
            rand::seq::index::sample(rng, pubkeys - first_n, pick_threshold - pick_first_n);
        for i in additional {
            res.push(i + first_n);
        }
    }
    res
}
