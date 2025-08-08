use crate::cell_message::cell::MoleculeStructFlag;
use serde::{Serialize, Deserialize};
use serde_with::{serde_as, Bytes};
use crate::impl_cell_methods;

pub const SPHINCSPLUS_PK_SIZE: usize = 32;
pub const SPHINCSPLUS_SIGN_SIZE: usize = 29792;

#[derive(PartialEq, Debug)]
pub struct SphincsplusDataCell {
    pub lock_arg: u8,
    pub type_arg: Option<[u8; 32]>,
    pub data: SphincsplusData,
    pub witness: Option<SphincsplusWitness>,
    pub struct_flag: MoleculeStructFlag,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct SphincsplusData {
    /// 主要是公钥，通常64字节
    #[serde_as(as = "Bytes")]
    pub pubkey: [u8; SPHINCSPLUS_PK_SIZE],
    // 你如果有 amount/owner/nonce 可补充此处
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct SphincsplusWitness {
    /// 通常 input_type 放签名
    pub input_type: Vec<u8>,    // 可以用 [u8; SPHINCSPLUS_SIGN_SIZE]，但 Vec 更灵活
    pub output_type: Vec<u8>,   // 通常可选，也许为空
}

impl SphincsplusDataCell {
    pub(crate) fn default() -> Self {
        SphincsplusDataCell {
            lock_arg: 0,
            type_arg: None,
            data: SphincsplusData {
                pubkey: [0u8; SPHINCSPLUS_PK_SIZE],
            },
            witness: None,
            struct_flag: MoleculeStructFlag {
                lock_arg: true,
                type_arg: true,
                data: true,
                witness: true,
            },
        }
    }

    pub fn new(type_arg: [u8; 32], data: SphincsplusData) -> Self {
        SphincsplusDataCell {
            lock_arg: 0,
            type_arg: Some(type_arg),
            data,
            witness: None,
            struct_flag: MoleculeStructFlag {
                lock_arg: true,
                type_arg: true,
                data: true,
                witness: true,
            },
        }
    }

    pub fn with_witness(mut self, witness: SphincsplusWitness) -> Self {
        self.witness = Some(witness);
        self
    }
}

impl_cell_methods!(SphincsplusDataCell);
