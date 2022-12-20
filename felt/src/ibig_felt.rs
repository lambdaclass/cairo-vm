use std::ops::Shr;

use ibig::{ibig, modular::ModuloRing, IBig, UBig};
use lazy_static::lazy_static;
use serde::Deserialize;

use crate::{Felt, NewFelt, ParseFeltError, FIELD};

lazy_static! {
    pub static ref CAIRO_MODULO_RING: ModuloRing =
        ModuloRing::new(&((UBig::from(FIELD.0) << 128) + UBig::from(FIELD.1)));
}

#[derive(Eq, Hash, PartialEq, PartialOrd, Ord, Clone, Debug, Deserialize, Default)]
pub struct FeltIBig(UBig);

impl<T: Into<IBig>> From<T> for FeltIBig {
    fn from(value: T) -> Self {
        Self(CAIRO_MODULO_RING.from(value.into()).residue())
    }
}

#[cfg(test)]
mod tests {
    use ibig::ubig;

    use super::*;

    #[test]
    fn create_feltibig() {
        let a = FeltIBig::from(1);
        assert_eq!(a.0, ubig!(1))
    }
}
