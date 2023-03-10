#[macro_use]
pub extern crate alloc;

pub mod with_alloc {
    pub use alloc::borrow;
    pub use alloc::boxed;
    pub use alloc::rc;
    pub use alloc::string;
    pub use alloc::sync;
    pub use alloc::vec;

    pub mod collections {
        pub use hashbrown::{HashMap, HashSet};
    }
}
