use num_traits::One;

use crate::stdlib::collections::HashMap;
use crate::stdlib::prelude::*;

use crate::types::relocatable::MaybeRelocatable;
use crate::vm::errors::hint_errors::HintError;
use crate::Felt252;
use crate::{types::relocatable::Relocatable, vm::vm_core::VirtualMachine};

/// Stores the data of a specific dictionary.
pub struct DictTrackerExecScope {
    /// The data of the dictionary.
    data: HashMap<Felt252, MaybeRelocatable>,
    /// The start of the segment of the dictionary.
    start: Relocatable,
    /// The end of this segment, if finalized.
    end: Option<Relocatable>,
}

/// Helper object to allocate, track and destruct all dictionaries in the run.
#[derive(Default)]
pub struct DictManagerExecScope {
    /// Maps between a segment index and the DictTrackerExecScope associated with it.
    segment_to_tracker: HashMap<isize, usize>,
    /// The actual trackers of the dictionaries, in the order of allocation.
    trackers: Vec<DictTrackerExecScope>,
}

impl DictTrackerExecScope {
    /// Creates a new tracker starting at `start`.
    pub fn new(start: Relocatable) -> Self {
        Self {
            data: HashMap::default(),
            start,
            end: None,
        }
    }
}

impl DictManagerExecScope {
    pub const DICT_DEFAULT_VALUE: usize = 0;

    /// Allocates a new segment for a new dictionary and return the start of the segment.
    pub fn new_default_dict(&mut self, vm: &mut VirtualMachine) -> Result<Relocatable, HintError> {
        let dict_segment = vm.add_temporary_segment();
        let tracker = DictTrackerExecScope::new(dict_segment);
        assert!(self
            .segment_to_tracker
            .insert(dict_segment.segment_index, self.trackers.len())
            .is_none());

        self.trackers.push(tracker);
        Ok(dict_segment)
    }

    /// Returns a mut reference for a dict tracker corresponding to a given pointer to a dict
    /// segment.
    fn get_dict_tracker_mut(&mut self, dict_end: Relocatable) -> &mut DictTrackerExecScope {
        let idx = self
            .get_dict_infos_index(dict_end)
            .expect("The given value does not point to a known dictionary.");
        &mut self.trackers[idx]
    }

    /// Returns the index of the dict tracker corresponding to a given pointer to a dict segment.
    pub fn get_dict_infos_index(&self, dict_end: Relocatable) -> Result<usize, HintError> {
        Ok(*self
            .segment_to_tracker
            .get(&dict_end.segment_index)
            .ok_or_else(|| {
                HintError::CustomHint(
                    "The given value does not point to a known dictionary."
                        .to_string()
                        .into_boxed_str(),
                )
            })?)
    }

    /// Finalizes a segment of a dictionary.
    pub fn finalize_segment(&mut self, dict_end: Relocatable) -> Result<(), HintError> {
        let tracker_idx = self.get_dict_infos_index(dict_end)?;
        let tracker = &mut self.trackers[tracker_idx];
        if let Some(prev) = tracker.end {
            return Err(HintError::CustomHint(
                format!(
                    "The segment is already finalized. \
                    Attempting to override next start {prev}, with: {dict_end}.",
                )
                .into_boxed_str(),
            ));
        }
        tracker.end = Some(dict_end);
        Ok(())
    }

    /// Relocates all dictionaries into a single segment
    pub fn relocate_all_dictionaries(&mut self, vm: &mut VirtualMachine) -> Result<(), HintError> {
        let mut prev_end = vm.add_memory_segment();
        for tracker in &self.trackers {
            vm.add_relocation_rule(tracker.start, prev_end)?;
            prev_end += (tracker.end.unwrap() - tracker.start)?;
            prev_end += 1;
        }
        Ok(())
    }

    /// Inserts a value to the dict tracker corresponding to a given pointer to a dict segment.
    pub fn insert_to_tracker(
        &mut self,
        dict_end: Relocatable,
        key: Felt252,
        value: MaybeRelocatable,
    ) {
        self.get_dict_tracker_mut(dict_end).data.insert(key, value);
    }

    /// Gets a value from the dict tracker corresponding to a given pointer to a dict segment.
    /// None if the key does not exist in the tracker data.
    pub fn get_from_tracker(
        &self,
        dict_end: Relocatable,
        key: &Felt252,
    ) -> Option<MaybeRelocatable> {
        self.trackers[self.get_dict_infos_index(dict_end).ok()?]
            .data
            .get(key)
            .cloned()
    }
}

/// Helper object for the management of dict_squash hints.
#[derive(Default, Debug)]
pub struct DictSquashExecScope {
    /// A map from key to the list of indices accessing it, each list in reverse order.
    pub(crate) access_indices: HashMap<Felt252, Vec<Felt252>>,
    /// Descending list of keys.
    pub(crate) keys: Vec<Felt252>,
}

impl DictSquashExecScope {
    /// Returns the current key to process.
    pub fn current_key(&self) -> Option<Felt252> {
        self.keys.last().cloned()
    }

    /// Removes the current key, and its access indices. Should be called when only the
    /// last key access is in the corresponding indices list.
    pub fn pop_current_key(&mut self) -> Result<(), HintError> {
        let current_key = self.current_key().ok_or_else(|| {
            HintError::CustomHint("Failed to get current key".to_string().into_boxed_str())
        })?;
        let key_accesses = self.access_indices.remove(&current_key).ok_or_else(|| {
            HintError::CustomHint(format!("No key accesses for key {current_key}").into_boxed_str())
        })?;
        if !key_accesses.len().is_one() {
            return Err(HintError::CustomHint(
                "Key popped but not all accesses were processed."
                    .to_string()
                    .into_boxed_str(),
            ));
        }
        self.keys.pop();
        Ok(())
    }

    /// Returns a reference to the access indices list of the current key.
    pub fn current_access_indices(&mut self) -> Option<&mut Vec<Felt252>> {
        let current_key = self.current_key()?;
        self.access_indices.get_mut(&current_key)
    }

    /// Returns a reference to the last index in the current access indices list.
    pub fn current_access_index(&mut self) -> Option<&Felt252> {
        self.current_access_indices()?.last()
    }

    /// Returns and removes the current access index.
    pub fn pop_current_access_index(&mut self) -> Option<Felt252> {
        self.current_access_indices()?.pop()
    }
}
