impl HintExecutor for BuiltinHintExecutor {

fn compile_hint(&self, hint_code: &str,ap_tracking_data:&ApTracking, reference_ids: HashMap<String, BigInt>, references: &HashMap<usize, HintReference>) -> Box<dyn Any>{
        
    HintData {
        hint_code,
        hint_ap_tracking,

    }
}
}
