use crate::stdlib::{collections::BTreeMap, prelude::*};
use crate::types::builtin_name::BuiltinName;
use crate::types::relocatable::MaybeRelocatable;
use crate::vm::trace::trace_entry::TraceEntry;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

//* ----------------------
//*   ProverInputInfo
//* ----------------------
/// This struct contains all relevant data for the prover.
/// All addresses are relocatable.
#[derive(Deserialize, Serialize, PartialEq)]
pub struct ProverInputInfo {
    /// A vector of trace entries, i.e. pc, ap, fp, where pc is relocatable.
    pub relocatable_trace: Vec<TraceEntry>,
    /// A vector of segments, where each segment is a vector of maybe relocatable values or holes (`None`).
    pub relocatable_memory: Vec<Vec<Option<MaybeRelocatable>>>,
    /// A map from segment index to a vector of offsets within the segment, representing the public memory addresses.
    pub public_memory_offsets: BTreeMap<usize, Vec<usize>>,
    /// A map from the builtin segment index into its name.
    pub builtins_segments: BTreeMap<usize, BuiltinName>,
}

impl ProverInputInfo {
    pub fn serialize_json(&self) -> Result<String, ProverInputInfoError> {
        serde_json::to_string_pretty(&self).map_err(ProverInputInfoError::from)
    }
    pub fn serialize(&self) -> Result<Vec<u8>, ProverInputInfoError> {
        bincode::serde::encode_to_vec(self, bincode::config::standard())
            .map_err(ProverInputInfoError::from)
    }
}

#[derive(Debug, Error)]
pub enum ProverInputInfoError {
    #[error("Failed to (de)serialize data using bincode")]
    SerdeBincode(#[from] bincode::error::EncodeError),
    #[error("Failed to (de)serialize data using json")]
    SerdeJson(#[from] serde_json::Error),
    #[error("Trace was not enabled")]
    TraceNotEnabled,
}
