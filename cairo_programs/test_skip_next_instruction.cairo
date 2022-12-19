func main{}() {
  alloc_locals;
  local x;
  // This assertion will be skipped by vm.skip_next_instruction_execution
  %{
      x = 0
      vm.run_context.pc += 2
      vm.skip_instruction_execution = True
  %}
  // This is an instruction of size 1
  [ap] = 4;
  [ap] = 5, ap++;

  // This is an instruction of size 2
  %{
      x = 0
      vm.run_context.pc += 2
      vm.skip_instruction_execution = True
  %}
  call should_fail;

  x = 2;
  assert x = 2;
  return ();
}

func should_fail{}(a: felt) {
  assert a = 1512482385392052380;
  return ();
}
