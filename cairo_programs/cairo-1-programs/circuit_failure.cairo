use core::circuit::{
    RangeCheck96, AddMod, MulMod, u96, CircuitElement, CircuitInput, circuit_add,
    circuit_sub, circuit_mul, circuit_inverse, EvalCircuitTrait, u384,
    CircuitOutputsTrait, CircuitModulus, AddInputResultTrait, CircuitInputs,
};

fn main() -> u384 {
    let in1 = CircuitElement::<CircuitInput<0>> {};
    let in2 = CircuitElement::<CircuitInput<1>> {};
    let add1 = circuit_add(in1, in2);
    let sub1 = circuit_sub(add1, add1);
    let inv1 = circuit_inverse(sub1);
    let modulus = TryInto::<_, CircuitModulus>::try_into([17, 14, 14, 14]).unwrap();

    let outputs = (inv1,)
        .new_inputs()
        .next([9, 2, 9, 3])
        .next([5, 7, 0, 8])
        .done()
        .eval(modulus)
        .unwrap();

    outputs.get_output(sub1)
}
