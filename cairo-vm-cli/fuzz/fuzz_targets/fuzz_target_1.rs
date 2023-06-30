#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::process::Command;
use std::fs;
use cairo_vm::cairo_run::{self, EncodeTraceError, CairoRunConfig};
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;

// Global counter for fuzz iteration
static FUZZ_ITERATION_COUNT: AtomicUsize = AtomicUsize::new(0);

fuzz_target!(|data: (u128, &[u8])| {

    // Define fuzzer iteration with id purposes
    let iteration_count = FUZZ_ITERATION_COUNT.fetch_add(1, Ordering::SeqCst);

    // Define default configuration
    let cairo_run_config = CairoRunConfig::default();
    let mut hint_executor = BuiltinHintProcessor::new_empty();

    // Create content of the programs
    let cairo_content_array_sum = program_content_array_sum(data.0.to_string());
    let cairo_content_random = program_content_random(data.1);
    let cairo_content_serialize_word = program_content_serialize_word(data.0.to_string());
    let cairo_content_unsafe_keccak = program_content_unsafe_keccak(data.0.to_string());

    // Create programs names and program
    let cairo_path_array_sum = format!("fuzz/cairo_programs/array_sum-{}.cairo", iteration_count);
    let json_path_array_sum = format!("fuzz/cairo_programs/array_sum-{}.json", iteration_count);
    let _ = fs::write(&cairo_path_array_sum, cairo_content_array_sum.as_bytes());

    let cairo_path_random = format!("fuzz/cairo_programs/random-{}.cairo", iteration_count);
    let json_path_random= format!("fuzz/cairo_programs/random-{}.json", iteration_count);
    let _ = fs::write(&cairo_path_random, cairo_content_random.as_bytes());

    let cairo_path_serialize_word = format!("fuzz/cairo_programs/serialize_word-{}.cairo", iteration_count);
    let json_path_serialize_word= format!("fuzz/cairo_programs/serialize_word-{}.json", iteration_count);
    let _ = fs::write(&cairo_path_serialize_word, cairo_content_serialize_word.as_bytes());

    let cairo_path_unsafe_keccak = format!("fuzz/cairo_programs/unsafe_keccak-{}.cairo", iteration_count);
    let json_path_unsafe_keccak = format!("fuzz/cairo_programs/unsafe_keccak-{}.json", iteration_count);
    let _ = fs::write(&cairo_path_unsafe_keccak, cairo_content_unsafe_keccak.as_bytes());

    // Get .json file with .cairo file
    let _output_array_sum = Command::new("cairo-compile")
                .arg(cairo_path_array_sum.clone())
                .arg("--output")
                .arg(json_path_array_sum.clone())
                .output()
                .expect("failed to execute process");

    let program_content_array_sum = std::fs::read(&json_path_array_sum).unwrap();

    let _output_random = Command::new("cairo-compile")
                .arg(cairo_path_random.clone())
                .arg("--output")
                .arg(json_path_random.clone())
                .output()
                .expect("failed to execute process");

    let program_content_random = std::fs::read(&json_path_random).unwrap();

    let _output_serialize_word = Command::new("cairo-compile")
                .arg(cairo_path_serialize_word.clone())
                .arg("--output")
                .arg(json_path_serialize_word.clone())
                .output()
                .expect("failed to execute process");

    let program_content_serialize_word = std::fs::read(&json_path_serialize_word).unwrap();

    let _output_unsafe_keccak = Command::new("cairo-compile")
                .arg(cairo_path_unsafe_keccak.clone())
                .arg("--output")
                .arg(json_path_unsafe_keccak.clone())
                .output()
                .expect("failed to execute process");

    let program_content_unsafe_keccak = std::fs::read(&json_path_unsafe_keccak).unwrap();

    // Run the program with default configurations
    cairo_run::cairo_run(&program_content_array_sum, &cairo_run_config, &mut hint_executor);
    cairo_run::cairo_run(&program_content_random, &cairo_run_config, &mut hint_executor);
    cairo_run::cairo_run(&program_content_serialize_word, &cairo_run_config, &mut hint_executor);
    cairo_run::cairo_run(&program_content_unsafe_keccak, &cairo_run_config, &mut hint_executor);

    // Remove files to save memory
    fs::remove_file(cairo_path_array_sum);
    fs::remove_file(json_path_array_sum);
    fs::remove_file(cairo_path_random);
    fs::remove_file(json_path_random);
    fs::remove_file(cairo_path_serialize_word);
    fs::remove_file(json_path_serialize_word);
    // fs::remove_file(cairo_path_unsafe_keccak);
    // fs::remove_file(json_path_unsafe_keccak);

});

fn program_content_array_sum(array: String) -> String {

    let mut populated_array = array
        .chars()
        .enumerate()
        .map(|(index, num)| format!("assert [ptr + {}] = {} \n", index, num))
        .collect::<Vec<_>>()
        .join("            ")
        .repeat(array.len());


    let file_content = format!("
        %builtins output

        from starkware.cairo.common.alloc import alloc
        from starkware.cairo.common.serialize import serialize_word
        
        // Computes the sum of the memory elements at addresses:
        //   arr + 0, arr + 1, ..., arr + (size - 1).
        func array_sum(arr: felt*, size) -> (sum: felt) {{
            if (size == 0) {{
                return (sum=0);
            }}
        
            // size is not zero.
            let (sum_of_rest) = array_sum(arr=arr + 1, size=size - 1);
            return (sum=[arr] + sum_of_rest);
        }}
        
        func main{{output_ptr: felt*}}() {{
            const ARRAY_SIZE = {};
        
            // Allocate an array.
            let (ptr) = alloc();
        
            // Populate some values in the array.
            {}
        
            // Call array_sum to compute the sum of the elements.
            let (sum) = array_sum(arr=ptr, size=ARRAY_SIZE);
        
            // Write the sum to the program output.
            serialize_word(sum);
        
            return ();
    }}
    ", array.len(), populated_array);

    file_content
}

fn program_content_random(rand: &[u8]) -> String {
    format!("
    func main() {{
        {:?}
    }}
    
    ", String::from_utf8_lossy(rand))
}

fn program_content_serialize_word(num: String) -> String {
    format!("
    %builtins output

    from starkware.cairo.common.serialize import serialize_word

    func main{{output_ptr: felt*}}() {{

        serialize_word({});

        ret;
    }} 
    ", num)
}

fn program_content_unsafe_keccak(array: String) -> String {

    let mut populated_array = array
        .chars()
        .enumerate()
        .map(|(index, num)| format!("assert data[{}] = {} \n", index, num.to_string().repeat(array.len() - (index + 1))))
        .collect::<Vec<_>>()
        .join("            ");

    format!("
    %builtins output

    from starkware.cairo.common.alloc import alloc
    from starkware.cairo.common.serialize import serialize_word
    from starkware.cairo.common.keccak import unsafe_keccak

    func main{{output_ptr: felt*}}() {{
        alloc_locals;

        let (data: felt*) = alloc();

        {}

        let (low: felt, high: felt) = unsafe_keccak(data, {});

        serialize_word(low);
        serialize_word(high);

        return ();
    }}
    ", populated_array, array.len())
}
