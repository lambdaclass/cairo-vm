#!/usr/bin/env sh

tests_path="../cairo_programs"
exit_code=0
trace=false
memory=false
declare -i passed_tests=0
declare -i failed_tests=0

for i in $@; do
    case $i in
        "trace") trace=true
        ;;
        "memory") memory=true
        ;;
        *)
        ;;
    esac
done

if $trace; then
    for file in $(ls $tests_path | grep .cleopatra.trace | sed -E 's/\.cleopatra\.trace//'); do
        if ! diff -q $tests_path/$file{,.cleopatra}.trace; then
            echo "Traces for $file differ"
            exit_code=1
            failed_tests+=1
        else
            passed_tests+=1
        fi
    done
fi

if $memory; then
    for file in $(ls $tests_path | grep .cleopatra.memory | sed -E 's/\.cleopatra\.memory//'); do
            if ! ./memory_comparator.py $tests_path/$file{,.cleopatra}.memory > /dev/null 2>&1; then
            echo "Memory differs for $file"
            exit_code=1
            failed_tests+=1
        else
            passed_tests+=1
        fi
    done
fi

if (($failed_tests == 0)); then
    echo "All $passed_tests tests passed; no discrepancies found"
else
        echo "Comparisons: $failed_tests failed, $passed_tests passed, $(($failed_tests + $passed_tests)) total" 
fi

exit "${exit_code}"
