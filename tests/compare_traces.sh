#!/bin/sh

test_files=($(ls -p ../cairo_programs | grep -v / | sed -E 's/\.cairo//'))

cargo build --release

for file in ${test_files[@]}; do
    cairo-compile "../cairo_programs/$file.cairo" --output "$file.json"

    cairo_output=$( (cairo-run --layout all --print_output --program "$file.json" --trace_file "$file.trace") | tr -dc 0-9 ) 
    cleopatra_output=$( (../target/release/cleopatra-run --print_output "$file.json" --trace-file "$file.cleopatra.trace") | tr -dc 0-9 )

    if [[ $cairo_output != $cleopatra_output ]]; then
        echo "Warning: Cairo output ($cairo_output) and Cleopatra output ($cleopatra_output) differ"
    fi

    if ! diff -q $file{,.cleopatra}.trace; then
        echo "Traces for $file differ"
        exit 1
    else
        echo "Traces for $file match"
    fi
done

rm *.trace
rm *.json
