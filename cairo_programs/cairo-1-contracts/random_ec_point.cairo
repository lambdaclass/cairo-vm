#[contract]
mod RandomEcPoint{
    use option::OptionTrait;
    use ec::ec_state_init;

    #[external]
    fn random_ec_point(){
        let state = ec_state_init();
    }

}
