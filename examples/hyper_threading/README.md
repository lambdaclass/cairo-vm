# Hyper-Threading Benchmarks for Cairo-VM

## Overview
This crate is designed to benchmark the performance of Cairo-VM in a hyper-threaded environment. By leveraging the [Rayon library](https://docs.rs/rayon/latest/rayon/), we can transform sequential computations into parallel ones, maximizing the utilization of available CPU cores.

### Running Benchmarks
To execute the benchmarks, navigate to the project's root directory and run the following command:

```bash
make hyper-threading-benchmarks
```
