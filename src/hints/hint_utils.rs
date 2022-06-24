use crate::hints::execute_hint::Env;
use crate::types::relocatable::MaybeRelocatable;

//Temporary helper native functions for WASM hint execution, will be later replaced with VM methods

//Acts as a connection between addition of a segment and insertion of its first address into memory
//Will be removed once MaybeRelocatables can be encoded and sent between functions inside WASM
pub fn add_segment(env: &Env) {
    let mut segments = env.segments.lock().unwrap();
    let mut memory = env.memory.lock().unwrap();
    let ap = env.ap.lock().unwrap();
    let rel = segments.add(&mut (*memory), None);
    (*memory)
        .insert(&*ap, &MaybeRelocatable::RelocatableValue(rel))
        .unwrap();
}
