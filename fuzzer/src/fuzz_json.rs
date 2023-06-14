use honggfuzz::fuzz;
mod utils;
use crate::utils::{run, Args};

fn main() {
    loop {
        fuzz!(|data: (Args, Vec<u8>)| {
            let _ = run(data);
        });
    }
}
