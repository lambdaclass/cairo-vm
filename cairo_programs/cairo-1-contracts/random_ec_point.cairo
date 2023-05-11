#[contract]
mod RandomEcPoint{
    use option::OptionTrait;
    use ec::ec_state_init;
    use ec::ec_state_add;
    use ec::ec_state_try_finalize_nz;
    use ec::ec_point_from_x;
    use ec::ec_point_non_zero;
    use ec::ec_point_unwrap;

    // Test taken from https://github.com/starkware-libs/cairo/blob/a0ead7c0b8e297d281c7213151cd43ac11de5042/corelib/src/test/ec_test.cairo#L17
    #[external]
    fn random_ec_point() -> felt252{
        // Beta + 2 is a square, and for x = 1 and alpha = 1, x^3 + alpha * x + beta = beta + 2.
        let beta_p2_root = 2487829544412206244690656897973144572467842667075005257202960243805141046681;

        let p = ec_point_from_x(1).unwrap();
        let p_nz = ec_point_non_zero(p);

        let mut state = ec_state_init();
        ec_state_add(ref state, p_nz);

        let q = ec_state_try_finalize_nz(state).expect('zero point');
        let (qx, qy) = ec_point_unwrap(q);

        assert(qx == 1, 'bad finalize x');
        assert(qy == beta_p2_root, 'bad finalize y');
        qx
    }

}
