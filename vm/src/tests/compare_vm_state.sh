#!/usr/bin/env sh

# move to the directory where the script is located
cd $(dirname "$0")

tests_path="../../../cairo_programs"
proof_tests_path="${tests_path}/proof_programs"
exit_code=0
trace=false
memory=false
air_public_input=false
passed_tests=0
failed_tests=0

for i in $@; do
    case $i in
        "trace") trace=true
        echo "Requested trace comparison"
        ;;
        "memory") memory=true
        echo "Requested memory comparison"
        ;;
        "proof_mode") tests_path=$proof_tests_path
        echo "Requested proof mode usage"
        ;;
        "air_public_input") air_public_input=true
        echo "Requested air_public_input comparison"
        ;;
        *)
        ;;
    esac
done

if $air_public_input; then
    if [ $tests_path != $proof_tests_path ]; then
        echo "Can't compare air_public_input without proof_mode"
        exit 1
    fi
fi

files=$(ls $tests_path)
EXIT_CODE=$?
if [ ${EXIT_CODE} != 0 ]; then
    exit ${EXIT_CODE}
fi

for file in $(ls $tests_path | grep .cairo$ | sed -E 's/\.cairo$//'); do
    path_file="$tests_path/$file"

    if $trace; then
        if ! diff -q $path_file.trace $path_file.rs.trace; then
            echo "Traces for $file differ"
            exit_code=1
            failed_tests=$((failed_tests + 1))
        else
            passed_tests=$((passed_tests + 1))
        fi
    fi

    if $memory; then
        if ! ./memory_comparator.py $path_file.memory $path_file.rs.memory; then
            echo "Memory differs for $file"
            exit_code=1
            failed_tests=$((failed_tests + 1))
        else
            passed_tests=$((passed_tests + 1))
        fi
    fi

    if $air_public_input; then
        if ! ./air_public_input_comparator.py $path_file.air_public_input $path_file.rs.air_public_input; then
            echo "Air Public Input differs for $file"
            exit_code=1
            failed_tests=$((failed_tests + 1))
        else
            passed_tests=$((passed_tests + 1))
        fi
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
