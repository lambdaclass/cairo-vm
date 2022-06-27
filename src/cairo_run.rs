use crate::types::program::Program;
use crate::vm::errors::cairo_run_errors::CairoRunError;
use crate::vm::runners::cairo_runner::CairoRunner;
use crate::vm::trace::trace_entry::RelocatedTraceEntry;
use num_bigint::BigInt;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

pub fn cairo_run(path: &Path) -> Result<CairoRunner, CairoRunError> {
    let program = match Program::new(path) {
        Ok(program) => program,
        Err(error) => return Err(CairoRunError::Program(error)),
    };

    let mut cairo_runner = CairoRunner::new(&program);
    cairo_runner.initialize_segments(None);

    let end = match cairo_runner.initialize_main_entrypoint() {
        Ok(end) => end,
        Err(error) => return Err(CairoRunError::Runner(error)),
    };

    if let Err(error) = cairo_runner.initialize_vm() {
        return Err(CairoRunError::Runner(error));
    }

    if let Err(error) = cairo_runner.run_until_pc(end) {
        return Err(CairoRunError::VirtualMachine(error));
    }

    if let Err(error) = cairo_runner.vm.verify_auto_deductions() {
        return Err(CairoRunError::VirtualMachine(error));
    }

    if let Err(error) = cairo_runner.relocate() {
        return Err(CairoRunError::Trace(error));
    }

    Ok(cairo_runner)
}

pub fn write_output(cairo_runner: &mut CairoRunner) -> Result<(), CairoRunError> {
    if let Err(error) = cairo_runner.write_output(&mut io::stdout()) {
        return Err(CairoRunError::Runner(error));
    }
    Ok(())
}

/// Writes a trace as a binary file. Bincode encodes to little endian by default and each trace
/// entry is composed of 3 usize values that are padded to always reach 64 bit size.
pub fn write_binary_trace(relocated_trace: &[RelocatedTraceEntry], trace_file: &Path) {
    let mut buffer = File::create(trace_file).expect("Error while creating trace file");
    for (i, entry) in relocated_trace.iter().enumerate() {
        if let Err(e) = bincode::serialize_into(&mut buffer, entry) {
            println!(
                "Failed to dump trace at position {}, serialize error: {}",
                i, e
            );
        }
    }
}

/*
   Writes a binary memory file with the relocated memory as input.
   The memory pairs (address, value) are encoded and concatenated in the file
   given by the path `memory_file`.

    * address -> 8-byte encoded
    * value -> 32-byte encoded
*/
pub fn write_binary_memory(
    relocated_memory: &[Option<BigInt>],
    memory_file: &Path,
) -> io::Result<()> {
    let mut buffer = File::create(memory_file).expect("Error while creating memory file");

    // initialize bytes vector that will be dumped to file
    let mut memory_bytes: Vec<u8> = Vec::new();

    for (i, memory_cell) in relocated_memory.iter().filter(|x| !x.is_none()).enumerate() {
        match memory_cell {
            None => continue,
            Some(unwrapped_memory_cell) => {
                encode_relocated_memory(&mut memory_bytes, i, unwrapped_memory_cell);
            }
        }
    }

    match buffer.write(&memory_bytes) {
        Err(e) => Err(e),
        Ok(_) => Ok(()),
    }
}

// encodes a given memory cell.
fn encode_relocated_memory(memory_bytes: &mut Vec<u8>, addr: usize, memory_cell: &BigInt) {
    // append memory address to bytes vector using a 8 bytes representation
    let mut addr_bytes = (addr as u64 + 1).to_le_bytes().to_vec();
    memory_bytes.append(&mut addr_bytes);

    // append memory value at address using a 32 bytes representation
    let mut value_bytes = memory_cell.to_signed_bytes_le();
    value_bytes.resize(32, 0);
    memory_bytes.append(&mut value_bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_binary_trace_file() {
        let program_path = Path::new("tests/support/struct.json");
        let serialized_trace_filename = "tests/support/struct_cleopatra.trace";
        let serialized_trace_path = Path::new(serialized_trace_filename.clone());
        let program = Program::new(program_path).expect("Couldn't open program");
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.initialize_segments(None);
        let end = cairo_runner
            .initialize_main_entrypoint()
            .expect("Couldn't initialize main entry point");
        cairo_runner
            .initialize_vm()
            .expect("Couldn't initialize VM");
        assert!(cairo_runner.run_until_pc(end) == Ok(()), "Execution failed");
        cairo_runner.relocate().expect("Couldn't relocate memory");
        write_binary_trace(&cairo_runner.relocated_trace, serialized_trace_path);

        let expected_trace_buffer = File::open("tests/support/struct.trace")
            .expect("Couldn't open python VM generated trace");
        let expected_trace: Vec<u8> = bincode::deserialize_from(&expected_trace_buffer)
            .expect("Couldn't deserialize python VM generated trace");
        let serialized_buffer =
            File::open(serialized_trace_filename).expect("Couldn't open rust VM generated trace");
        let serialized_program: Vec<u8> = bincode::deserialize_from(&serialized_buffer)
            .expect("Couldn't deserialize rust VM generated trace");

        assert!(expected_trace == serialized_program);
    }

    #[test]
    fn write_binary_memory_file() {
        let program_path = Path::new("tests/support/struct.json");
        let serialized_memory_filename = "tests/support/struct_cleopatra.memory";
        let serialized_memory_path = Path::new(serialized_memory_filename.clone());
        let program = Program::new(program_path).expect("Couldn't open program");
        let mut cairo_runner = CairoRunner::new(&program);
        cairo_runner.initialize_segments(None);
        let end = cairo_runner
            .initialize_main_entrypoint()
            .expect("Couldn't initialize main entry point");
        cairo_runner
            .initialize_vm()
            .expect("Couldn't initialize VM");
        assert!(cairo_runner.run_until_pc(end) == Ok(()), "Execution failed");
        cairo_runner.relocate().expect("Couldn't relocate memory");
        write_binary_memory(&cairo_runner.relocated_memory, serialized_memory_path).unwrap();

        println!("Memory: {:?}", &cairo_runner.relocated_memory);

        let expected_memory_buffer = File::open("tests/support/struct.memory")
            .expect("Couldn't open python VM generated memory file");
        let expected_memory: Vec<u8> = bincode::deserialize_from(&expected_memory_buffer)
            .expect("Couldn't deserialize python VM generated trace");
        let serialized_buffer =
            File::open(serialized_memory_filename).expect("Couldn't open rust VM generated memory");
        let serialized_cleopatra_memory: Vec<u8> = bincode::deserialize_from(&serialized_buffer)
            .expect("Couldn't deserialize rust VM generated memory");

        assert!(expected_memory == serialized_cleopatra_memory);
    }
}
