#!/bin/bash

## see directory
pwd

### Compile hyper_threading_pr
make cairo_bench_programs
cargo build --release -p hyper_threading
cp target/release/hyper_threading ./hyper_threading_pr


### Compile hyper_threading_pr
git checkout main
make cairo_bench_programs
cargo build --release -p hyper_threading
cp target/release/hyper_threading ./hyper_threading_main


# Define una lista con los valores deseados para RAYON_NUM_THREADS
thread_counts=(1 2 4 6 8 16 32)

# Define una lista con los nombres de los binarios
binaries=("hyper_threading_main" "hyper_threading_pr")

# Itera sobre la lista de thread_counts
for threads in "${thread_counts[@]}"; do
    # Inicia la construcción del comando hyperfine para este valor de threads
    cmd="hyperfine -r 1"
    
    # Agrega cada binario al comando con el valor actual de threads
    for binary in "${binaries[@]}"; do
        cmd+=" -n \"${binary} threads: ${threads}\" 'RAYON_NUM_THREADS=${threads} ./${binary}'"
    done
    
    # Ejecuta el comando hyperfine construido
    echo "Ejecutando benchmark para ${threads} threads"
    eval $cmd
done
