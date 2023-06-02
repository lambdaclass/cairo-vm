# Step by Step to benchmark lambdawork FieldElement:

## Create binaries
```
mkdir binaries
```

###  Create binary from main 
// Main las commit
```
git checkout de6a2327b7e629336bc2431787c8e28c3b0f1349 
```

```
cargo build -p cairo-vm-cli --release
```

```
mv target/release/cairo-vm-cli binaries/cairo-vm-cli-main
```

###  Create binary from lambdaworks-felt 

// lambdaworks-felt last commit (cambiarlo con el ultimo commit)
```
git checkout 6a8ca26cb20b3829db6ef1e298f27a3161642395 
```

```
cargo build -p cairo-vm-cli --release
```

```
mv target/release/cairo-vm-cli binaries/cairo-vm-cli-lambdaworks
```

## Compile cairo program
Install dependencies if neesary

Linux users
```
make deps
```

Mac users
```
make deps-macos
```

```
source cairo-rs-env/bin/activate
```

```
make cairo_bench_programs
```

## Run benchmarks
```
chmod +x lamdaworks-benchmarks.sh
```

```
sh lamdaworks-benchmarks.sh
```
