#!/usr/bin/env sh

factorial_compiled="cairo_programs/proof_programs/factorial.json"
passed_tests=0
failed_tests=0
exit_code=0

for layout in "plain" "small" "dex" "recursive" "starknet" "starknet_with_keccak" "recursive_large_output" "all_solidity" "starknet_with_keccak"; do
    # Run cairo_vm
    echo "Running cairo-vm with layout $layout"
    cargo run -p cairo-vm-cli --release -- --layout $layout --proof_mode $factorial_compiled --trace_file factorial_rs.trace --memory_file factorial_rs.memory --air_public_input factorial_rs.air_public_input --air_private_input factorial_rs.air_private_input
    # Run cairo_lang
    echo "Running cairo_lang with layout $layout"
    cairo-run --layout $layout --proof_mode  --program $factorial_compiled --trace_file factorial_py.trace --memory_file factorial_py.memory --air_public_input factorial_py.air_public_input --air_private_input factorial_py.air_private_input
    # Compare trace
    echo "Running trace comparison for layout $layout"
    if ! diff -q factorial_rs.trace factorial_py.trace; then
        echo "Trace differs for layout $layout"
        exit_code=1
        failed_tests=$((failed_tests + 1))
    else
        passed_tests=$((passed_tests + 1))
    fi
    # Compare memory
    echo "Running memory comparison for layout $layout"
    if ! ./vm/src/tests/memory_comparator.py factorial_rs.memory factorial_py.memory; then
        echo "Memory differs for layout $layout"
        exit_code=1
        failed_tests=$((failed_tests + 1))
    else
        passed_tests=$((passed_tests + 1))
    fi
    # Compare air public input
    echo "Running air public input  comparison for layout $layout"
    if ! ./vm/src/tests/air_public_input_comparator.py factorial_rs.air_public_input factorial_py.air_public_input; then
        echo "Air public input differs for layout $layout"
        exit_code=1
        failed_tests=$((failed_tests + 1))
    else
        passed_tests=$((passed_tests + 1))
    fi
    # Compare air private input
    echo "Running air private input  comparison for layout $layout"
    if ! ./vm/src/tests/air_private_input_comparator.py factorial_rs.air_private_input factorial_py.air_private_input; then
        echo "Air private input differs for layout $layout"
        exit_code=1
        failed_tests=$((failed_tests + 1))
    else
        passed_tests=$((passed_tests + 1))
    fi      

done

if test $failed_tests != 0; then
    echo "Comparisons: $failed_tests failed, $passed_tests passed, $((failed_tests + passed_tests)) total"
elif test $passed_tests = 0; then
    echo "No tests ran!"
    exit_code=2
else
    echo "All $passed_tests tests passed; no discrepancies found"
fi

exit "${exit_code}"
