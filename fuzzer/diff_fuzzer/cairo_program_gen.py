"""
Generate a cairo program with the following rules:
    1. Grab a hint
    2. Look for all the ids.(...) expressions, make sure to keep track of any "=" to the left or right
        - if none, go back to 1
    3. Reduce the ids.(...) expressions so that all the variables + their fields are grouped
    4. Create inputs and outputs variables dicts
        - inputs: if "=" was to the right
        - outputs: if "=" was to the left
    5. Create main using input variables
        - func main() {
            let a = MyStruct(field=1, field=2);
            hint_func();
            return();
          }
    6. Create hint_func with outputs as locals
        - hint_func(a: MyStruct) -> (MyStruct) {
            alloc_locals;
            local b: MyStruct;
            %{
              ...
            %}
            return(b);
          }
"""

def generate_cairo_hint_program(hint_code):
    input_vars = dict()
    output_vars = dict()
    lines = [line for line in hint_code.split("\n") if all(substr in line for substr in ["=", "ids."])]

    for line in lines:
        variables = [v[v.find("ids.") + len("ids."):] for v in line.split() if "ids." in v]
        dict_to_insert = input_vars if line.find("=") < line.find("ids.") else output_vars

        for var in variables:
            var_field = var.split(".")
            if len(var_field) == 1:
                dict_to_insert[var_field[0]] = []
            else:
                if not var_field[0] in dict_to_insert:
                    dict_to_insert[var_field[0]] = { var_field[1] }
                else:
                    dict_to_insert[var_field[0]].add(var_field[1])

    input_vars.update( (k, tuple(v)) for (k, v) in input_vars.items())
    output_vars.update( (k, tuple(v)) for (k, v) in output_vars.items())

    fields = { v for v in (input_vars | output_vars).values() if v != []}
    structs_dict = { v : "MyStruct" + str(i) for (i, v) in enumerate(fields) }

    structs_fmt = "struct {struct_name} {{\n{struct_fields}\n}}"
    fields_fmt = "\t{field_name}: felt,"

    declared_structs = "\n".join([
        structs_fmt.format(
            struct_name = name,
            struct_fields = "\n".join([fields_fmt.format(field_name=field_name) for field_name in fields])
        )
        for (fields, name) in structs_dict.items()
    ])


    main_func_fmt = "func main() {{\n{variables}\n\thint_func();\n\treturn();\n}}"
    main_var_assignment_fmt = "\tlet {var_name} = {struct_name}({assign_fields});"

    main_var_assignments = "\n".join([
        main_var_assignment_fmt.format(
            var_name = name,
            struct_name = structs_dict[var_fields],
            assign_fields = ", ".join([
                field_name + "=" for field_name in var_fields
            ])
        )
        for name, var_fields in input_vars.items()
    ])

    main_func = main_func_fmt.format(variables = main_var_assignments)

    hint_func_fmt = "hint_func{signature} {{\n\talloc_locals;\n{local_declarations}\n\t{hint}\n\treturn({output_return});\n}}"
    hint_input_var_fmt = "{var_name}: {struct_name}"
    local_declare_fmt = "\tlocal {res_var_name}: {res_struct};"

    signature = "(" + \
        ", ".join([
            hint_input_var_fmt.format(var_name = name, struct_name = structs_dict[var_fields]) for name, var_fields in input_vars.items()
        ]) + \
        ") -> (" + \
        ", ".join([structs_dict[var_fields] for var_fields in output_vars.values()]) + \
        ")"

    local_vars = "\n".join([
        local_declare_fmt.format(res_var_name = name, res_struct = structs_dict[var_fields]) for name, var_fields in output_vars.items()
    ])

    hint_func = hint_func_fmt.format(
        signature = signature, 
        local_declarations = local_vars, 
        hint = hint_code,
        output_return = ", ".join([res for res in output_vars.keys()])
    )

    return declared_structs.split("\n") + main_func.split("\n") + hint_func.split("\n")
