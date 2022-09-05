use std::str::FromStr;
use std::os::unix::net::UnixStream;
use std::io::prelude::*;

use num_bigint::BigInt;
use std::time::Instant;

#[derive(Clone, Debug)]
enum MaybeRelocatable {
    Int(BigInt),
}

#[derive(Clone, Debug)]
struct Memory {
    data: Vec<MaybeRelocatable>, 
}

impl Memory {
    fn new_filled() -> Memory {
        let mut mem = Memory { data: Vec::new() };

        for _ in 0..1000000 {
            mem.data.push(MaybeRelocatable::Int(BigInt::from_str("845284752492489284").unwrap()));
        }

        mem
    }
}

fn encode_memory(buff: &mut Vec<u8>, memory: &Memory) {
    for m in &memory.data {
        let MaybeRelocatable::Int(n) = m; 
        buff.append(&mut n.to_signed_bytes_be());
    }
}

fn main() {
    let mut stream = UnixStream::connect("ipc.sock").unwrap();

    let memory = Memory::new_filled();
    println!("Memory created");

    let mut m_bytes: Vec<u8> = Vec::new();

    encode_memory(&mut m_bytes, &memory);
    println!("Memory encoded");

    let now = Instant::now();
    stream.write_all(&m_bytes).unwrap();
    let elapsed = now.elapsed();

    println!("Time taken: {}s", elapsed.as_millis());
}
