//! An implementation of the Cairo virtual machine
//!
//! # Feature Flags
//! - `skip_next_instruction_hint`: Enable the `skip_next_instruction()` hint. Not enabled by default.
//! - `hooks`: Enable [Hooks](vm::hooks) support for the [VirtualMachine](vm::vm_core::VirtualMachine). Not enabled by default.
//! - `with_mimalloc`: Use [MiMalloc](https://crates.io/crates/mimalloc) as the program global allocator.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(warnings)]
pub mod cairo_run;
pub mod hint_processor;
pub mod math_utils;
pub mod serde;
pub mod types;
pub mod utils;
pub mod vm;
