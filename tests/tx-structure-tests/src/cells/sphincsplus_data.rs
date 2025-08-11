use serde::{Serialize, Deserialize};
use serde_with::{serde_as, Bytes};
use crate::cell_message::cell::MoleculeStructFlag;
use crate::impl_cell_methods;
use bincode;


pub const SPHINCSPLUS_PK_SIZE: usize = 48; // 修改成你最大可能的长度，或者保留32也行

impl SphincsplusData {
    pub fn as_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("SphincsplusData serialize failed")
    }
}
#[derive(PartialEq, Debug)]
pub struct SphincsplusDataCell {
    pub lock_arg: [u8; 32],
    pub type_arg: Option<[u8; 32]>,
    pub data: SphincsplusData,
    pub witness: Option<SphincsplusWitness>,
    pub struct_flag: MoleculeStructFlag,
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct SphincsplusData {
    /// 公钥，改为Vec<u8>支持动态长度
    #[serde_as(as = "Bytes")]
    pub pubkey: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct SphincsplusWitness {
    /// 通常 input_type 放签名
    pub input_type: Vec<u8>,    // 这里保持Vec<u8>
    pub output_type: Vec<u8>,   // 这里保持Vec<u8>
}

impl SphincsplusDataCell {
    pub(crate) fn default() -> Self {
        SphincsplusDataCell {
            lock_arg: [0u8; 32],
            type_arg: None,
            data: SphincsplusData {
                pubkey: vec![0u8; SPHINCSPLUS_PK_SIZE],  // 用vec初始化
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
            lock_arg: [0u8; 32],
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
