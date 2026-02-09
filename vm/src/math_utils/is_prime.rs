use num_bigint::BigUint;

pub fn is_prime(n: &BigUint) -> bool {
    num_prime::nt_funcs::is_prime::<BigUint>(n, None).probably()
}
