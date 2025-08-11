use ckb_fips205_utils::{
    ParamId, construct_flag,
    message::{HashAlgorithm, build_fips205_final_message},
    signing::{Sha2128F, Sha2128S, Sha2192F, Sha2256F, Shake128F, TxSigner, Sha2192S, Sha2256S, Shake128S, Shake192F, Shake192S, Shake256F, Shake256S},
};
use ckb_sphincs_utils::{SphincsPlus, sphincsplus::sphincs_plus_get_seed_size};
use ckb_testtool::bytes::Bytes;
use proptest::prelude::*;
use rand::{SeedableRng, rngs::StdRng};
use rand_core::CryptoRngCore;
use std::fmt;
use rand::Rng;

// We have extensive tests covering the signature verification process
// for all different kinds of parameter sets. Here we only select a handful
// of parameter sets to speed up tests.
pub enum Signer {
    C(SphincsPlus),
    Rust128F(Sha2128F),
    Rust192F(Sha2192F),
    Rust256F(Sha2256F),
    Rust128S(Sha2128S),
    RustShake128F(Shake128F),
    Rust192S(Sha2192S),
    Rust256S(Sha2256S),
    RustShake128S(Shake128S),
    RustShake192F(Shake192F),
    RustShake192S(Shake192S),
    RustShake256F(Shake256F),
    RustShake256S(Shake256S),
}

impl TxSigner for Signer {
    fn param_id(&self) -> ParamId {
        match self {
            Signer::C(_) => ckb_sphincs_utils::sphincsplus::param_id().unwrap(),
            Signer::Rust128F(s) => s.param_id(),
            Signer::Rust128S(s) => s.param_id(),
            Signer::Rust192F(s) => s.param_id(),
            Signer::Rust192S(s) => s.param_id(),
            Signer::Rust256F(s) => s.param_id(),
            Signer::Rust256S(s) => s.param_id(),
            Signer::RustShake128F(s) => s.param_id(),
            Signer::RustShake128S(s) => s.param_id(),
            Signer::RustShake192F(s) => s.param_id(),
            Signer::RustShake192S(s) => s.param_id(),
            Signer::RustShake256F(s) => s.param_id(),
            Signer::RustShake256S(s) => s.param_id(),
        }
    }

    fn public_key_bytes(&self) -> Bytes {
        match self {
            Signer::C(s) => Bytes::from(s.pk.clone()),
            Signer::Rust128F(s) => s.public_key_bytes(),
            Signer::Rust128S(s) => s.public_key_bytes(),
            Signer::Rust192F(s) => s.public_key_bytes(),
            Signer::Rust192S(s) => s.public_key_bytes(),
            Signer::Rust256F(s) => s.public_key_bytes(),
            Signer::Rust256S(s) => s.public_key_bytes(),
            Signer::RustShake128F(s) => s.public_key_bytes(),
            Signer::RustShake128S(s) => s.public_key_bytes(),
            Signer::RustShake192F(s) => s.public_key_bytes(),
            Signer::RustShake192S(s) => s.public_key_bytes(),
            Signer::RustShake256F(s) => s.public_key_bytes(),
            Signer::RustShake256S(s) => s.public_key_bytes(),
        }
    }

    fn sign_message<R: CryptoRngCore>(&self, rng: &mut R, message: &[u8]) -> Bytes {
        match self {
            Signer::C(s) => Bytes::from(s.sign(&build_fips205_final_message(
                HashAlgorithm::None,
                message,
                Some(&[]),
            ))),
            Signer::Rust128F(s) => s.sign_message(rng, message),
            Signer::Rust128S(s) => s.sign_message(rng, message),
            Signer::Rust192F(s) => s.sign_message(rng, message),
            Signer::Rust192S(s) => s.sign_message(rng, message),
            Signer::Rust256F(s) => s.sign_message(rng, message),
            Signer::Rust256S(s) => s.sign_message(rng, message),
            Signer::RustShake128F(s) => s.sign_message(rng, message),
            Signer::RustShake128S(s) => s.sign_message(rng, message),
            Signer::RustShake192F(s) => s.sign_message(rng, message),
            Signer::RustShake192S(s) => s.sign_message(rng, message),
            Signer::RustShake256F(s) => s.sign_message(rng, message),
            Signer::RustShake256S(s) => s.sign_message(rng, message),
        }
    }
}

impl fmt::Debug for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Signer::C(_) => write!(f, "sphincsplus-sha2-128f"),
            Signer::Rust128F(_) => write!(f, "fips205-sha2-128f"),
            Signer::Rust128S(_) => write!(f, "fips205-sha2-128s"),
            Signer::Rust192F(_) => write!(f, "fips205-sha2-192f"),
            Signer::Rust192S(_) => write!(f, "fips205-sha2-192s"),
            Signer::Rust256F(_) => write!(f, "fips205-sha2-256f"),
            Signer::Rust256S(_) => write!(f, "fips205-sha2-256s"),
            Signer::RustShake128F(_) => write!(f, "fips205-shake-128f"),
            Signer::RustShake128S(_) => write!(f, "fips205-shake-128s"),
            Signer::RustShake192F(_) => write!(f, "fips205-shake-192f"),
            Signer::RustShake192S(_) => write!(f, "fips205-shake-192s"),
            Signer::RustShake256F(_) => write!(f, "fips205-shake-256f"),
            Signer::RustShake256S(_) => write!(f, "fips205-shake-256s"),
        }
    }
}

pub fn build_multisig_header(
    signers: &[Signer],
    threshold: usize,
    require_first_n: usize,
) -> Bytes {
    let threshold: u8 = threshold.try_into().expect("overflow");
    let require_first_n: u8 = require_first_n.try_into().expect("overflow");
    let pubkeys: u8 = signers.len().try_into().expect("overflow");

    vec![0x80, require_first_n, threshold, pubkeys].into()
}

pub fn build_multisig_configuration(
    signers: &[Signer],
    threshold: usize,
    require_first_n: usize,
) -> Bytes {
    let mut res = vec![];
    res.extend(&build_multisig_header(signers, threshold, require_first_n));

    for signer in signers {
        res.push(construct_flag(signer.param_id(), false));
        res.extend(&signer.public_key_bytes());
    }

    Bytes::from(res)
}

pub fn signer_strategy() -> impl Strategy<Value=Signer> {
    prop_oneof![
        any::<u64>().prop_map(|seed| {
            let mut rng = StdRng::seed_from_u64(seed);
            let mut seed = vec![0; unsafe { sphincs_plus_get_seed_size() } as usize];
            rng.fill(&mut seed[..]);
            Signer::C(SphincsPlus::from(&seed))
        }),
        any::<u64>().prop_map(|seed| {
            let mut rng = StdRng::seed_from_u64(seed);
            Signer::Rust128F(Sha2128F::new(&mut rng))
        }),
        any::<u64>().prop_map(|seed| {
            let mut rng = StdRng::seed_from_u64(seed);
            Signer::Rust192F(Sha2192F::new(&mut rng))
        }),
        any::<u64>().prop_map(|seed| {
            let mut rng = StdRng::seed_from_u64(seed);
            Signer::Rust256F(Sha2256F::new(&mut rng))
        }),
        any::<u64>().prop_map(|seed| {
            let mut rng = StdRng::seed_from_u64(seed);
            Signer::Rust128S(Sha2128S::new(&mut rng))
        }),
        any::<u64>().prop_map(|seed| {
            let mut rng = StdRng::seed_from_u64(seed);
            Signer::RustShake128F(Shake128F::new(&mut rng))
        }),
        any::<u64>().prop_map(|seed| {
            let mut rng = StdRng::seed_from_u64(seed);
            Signer::Rust192S(Sha2192S::new(&mut rng))
        }),
        any::<u64>().prop_map(|seed| {
            let mut rng = StdRng::seed_from_u64(seed);
            Signer::Rust256S(Sha2256S::new(&mut rng))
        }),
        any::<u64>().prop_map(|seed| {
            let mut rng = StdRng::seed_from_u64(seed);
            Signer::RustShake128S(Shake128S::new(&mut rng))
        }),
        any::<u64>().prop_map(|seed| {
            let mut rng = StdRng::seed_from_u64(seed);
            Signer::RustShake192F(Shake192F::new(&mut rng))
        }),
        any::<u64>().prop_map(|seed| {
            let mut rng = StdRng::seed_from_u64(seed);
            Signer::RustShake192S(Shake192S::new(&mut rng))
        }),
        any::<u64>().prop_map(|seed| {
            let mut rng = StdRng::seed_from_u64(seed);
            Signer::RustShake256F(Shake256F::new(&mut rng))
        }),
        any::<u64>().prop_map(|seed| {
            let mut rng = StdRng::seed_from_u64(seed);
            Signer::RustShake256S(Shake256S::new(&mut rng))
        }),
    ]
}
