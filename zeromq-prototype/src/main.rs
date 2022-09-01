use num_bigint::BigInt;
use std::{env, time::Instant};
extern crate zmq;

struct Relocatable {
    segment_index: usize,
    offset: usize,
}

enum MaybeRelocatable {
    RelocatableValue(Relocatable),
    Int(BigInt),
}

struct Memory {
    data: Vec<Vec<MaybeRelocatable>>,
}

impl Memory {
    fn new(amount: usize) -> Memory {
        let mut data = Vec::new();
        for i in 0..4 {
            let mut seg = Vec::new();
            for j in 0..amount / 4 {
                if j % 4 == 0 {
                    seg.push(MaybeRelocatable::RelocatableValue(Relocatable { segment_index: i / 2, offset: j}));
                } else {
                    seg.push(MaybeRelocatable::Int(Into::<BigInt>::into(i * j * j)))
                }
            }
            data.push(seg);
        }

        Memory {
            data
        }
    }
}

fn encode_memory(memory_bytes: &mut Vec<u8>, memory: &Memory) {
    for segment in memory.data.iter() {
        for cell in segment.iter() {
            let mut byte_value = match cell {
                MaybeRelocatable::RelocatableValue(rel) => (Into::<BigInt>::into(rel.segment_index + rel.offset)).to_signed_bytes_le(),
                MaybeRelocatable::Int(n) => n.to_signed_bytes_le(),
            };
            memory_bytes.append(&mut byte_value);
        }
    }
}

fn main() {
    let args:Vec<String> = env::args().collect();
    let size = args[1].parse().unwrap();
    let m = Memory::new(size);    
    println!("Memory generated");

    let now = Instant::now();
    let mut m_bytes = Vec::new();
    encode_memory(&mut m_bytes, &m);
    println!("Memory encoded");

    let context= zmq::Context::new();
    let responder = context.socket(zmq::REQ).unwrap();
    assert!(responder.bind("tcp://*:5555").is_ok());

    let mut msg = zmq::Message::new();

    responder.send(m_bytes, 0).unwrap();
    responder.recv(&mut msg, 0).unwrap();

    let elapsed = now.elapsed();
    if elapsed.as_secs() > 1 {
        println!("Time taken: {}s", elapsed.as_secs());
    } else {
        println!("Time taken: {}ms", elapsed.as_millis());
    }
}
