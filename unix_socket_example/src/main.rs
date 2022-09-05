use std::io::prelude::*;
use std::os::unix::net::UnixStream;

use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Relocatable {
    pub segment_index: usize,
    pub offset: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum MaybeRelocatable {
    RelocatableValue(Relocatable),
    Int(usize),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Memory {
    data: Vec<MaybeRelocatable>,
}

impl Memory {
    fn new_filled() -> Memory {
        let mut mem = Memory { data: Vec::new() };

        for x in 0..1000000 {
            if x % 2 == 0 {
                mem.data.push(MaybeRelocatable::Int(10));
            } else {
                mem.data
                    .push(MaybeRelocatable::RelocatableValue(Relocatable {
                        segment_index: 2,
                        offset: 3,
                    }))
            }
        }
        mem
    }
}

fn main() {
    let mut stream = UnixStream::connect("ipc.sock").unwrap();

    let memory = Memory::new_filled();
    println!("Memory created");

    let serialized = serde_json::to_string(&memory).unwrap();

    let now = Instant::now();
    stream.write_all(serialized.as_bytes()).unwrap();

    let elapsed = now.elapsed();

    println!("Time taken: {}ms", elapsed.as_millis());
}
