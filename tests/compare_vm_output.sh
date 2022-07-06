#!/usr/bin/env sh

tests_path="../cairo_programs"
exit_code=0
trace=true

for i in $@; do
    case $i in
        "trace") trace=1
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
        else
            echo "Traces for $file match"
        fi
    done
fi

for file in $(ls $tests_path | grep .cleopatra.memory | sed -E 's/\.cleopatra\.memory//'); do
        if ! ./memory_comparator.py $tests_path/$file{,.cleopatra}.memory > /dev/null 2>&1; then
        echo "Memory differs for $file"
        exit_code=1
    else
        echo "Memory matches for $file"
    fi
done

exit "${exit_code}"
