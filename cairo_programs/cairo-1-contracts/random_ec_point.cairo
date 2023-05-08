#[contract]
mod RandomEcPoint{
    use option::OptionTrait;
    use ec::ec_state_init;
    use ec::ec_state_try_finalize_nz;
    use ec::ec_point_non_zero;

    #[external]
    fn random_ec_point(){
        let state = ec_state_init();
        let point_at_infinity = ec_state_try_finalize_nz(state);
        assert(point_at_infinity.is_none(), 'Wrong point');
    }

}