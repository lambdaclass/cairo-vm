tests_path="cairo_programs/benchmarks"

set -e

echo //////////////////////////////////////////////////
echo ////////// Compiling cairo-vm //////////
echo //////////////////////////////////////////////////
git checkout 0.9.2-jemallocator
cargo clean
cargo build -p cairo-vm-cli --release
mv target/release/cairo-vm-cli benchmarks/binaries/cairo-vm

echo //////////////////////////////////////////////////
echo ////////// Compiling cairo-vm + lambdaworks //////////
echo //////////////////////////////////////////////////
cargo clean
cargo build -p cairo-vm-cli --release -F lambdaworks-felt
mv target/release/cairo-vm-cli benchmarks/binaries/cairo-vm-lambdaworks



echo //////////////////////////////////////////////////
echo ////////// Compiling cairo-vm + mimalloc//////////
echo //////////////////////////////////////////////////
cargo clean
cargo build -p cairo-vm-cli --release -F with_mimalloc
mv target/release/cairo-vm-cli benchmarks/binaries/cairo-vm-mimalloc

echo //////////////////////////////////////////////////
echo ////////// Compiling cairo-vm + mimalloc + lambdaworks //////////
echo //////////////////////////////////////////////////
cargo clean
cargo build -p cairo-vm-cli --release -F lambdaworks-felt -F with_mimalloc
mv target/release/cairo-vm-cli benchmarks/binaries/cairo-vm-mimalloc-lambdaworks

echo //////////////////////////////////////////////////
echo ////////// Compiling cairo-vm with_jemalloc //////////
echo //////////////////////////////////////////////////

cargo clean
cargo build -p cairo-vm-cli --release -F with_jemalloc
mv target/release/cairo-vm-cli benchmarks/binaries/cairo-vm-jemalloc

echo //////////////////////////////////////////////////
echo ////////// Compiling cairo-vm with_jemalloc + lambdaworks //////////
echo //////////////////////////////////////////////////

cargo clean
cargo build -p cairo-vm-cli --release -F lambdaworks-felt -F with_jemalloc
mv target/release/cairo-vm-cli benchmarks/binaries/cairo-vm-jemalloc-lambdaworks


for file in $(ls $tests_path | grep .cairo | sed -E 's/\.cairo//'); do
    echo "Running $file benchmark"

    export PATH="$(pyenv root)/shims:$PATH"

hyperfine -n "Vanilla" "benchmarks/binaries/cairo-vm $tests_path/$file.json --layout starknet_with_keccak" \
 -n "Lambdaworks" "benchmarks/binaries/cairo-vm-lambdaworks $tests_path/$file.json --layout starknet_with_keccak" \
  -n "mimalloc" "benchmarks/binaries/cairo-vm-mimalloc $tests_path/$file.json --layout starknet_with_keccak" \
   -n "mimalloc + Lambdaworks" "benchmarks/binaries/cairo-vm-mimalloc-lambdaworks $tests_path/$file.json --layout starknet_with_keccak" \
    -n "jemalloc" "benchmarks/binaries/cairo-vm-jemalloc $tests_path/$file.json --layout starknet_with_keccak" \
     -n "jemalloc + Lambdaworks" "benchmarks/binaries/cairo-vm-jemalloc-lambdaworks $tests_path/$file.json --layout starknet_with_keccak" \
 -r 1 --show-output
done

