import ast
"""
Generate a cairo program with the following rules:
    1. Grab a hint
    2. Look for all the ids.(...) expressions, make sure to keep track of any assignments
    3. Reduce the ids.(...) expressions so that all the variables and their fields are 
        grouped
    4. Create variables dicts
        - declare_in_main: if the variable is used as assignee in the hint
        - declare_in_hint_fn: if the variable receives a value
    5. Create a list with all the constants called inside the hint that have to be imported
        from a cairo module
    6. Create main using declare_in_main
        - func main() {
            let a = MyStruct(field=1, field=2);
            hint_func();
            return();
          }
    7. Create hint_func with the variables in declare_in_hint_fn as locals
        - hint_func(a: MyStruct) -> (MyStruct) {
            alloc_locals;
            local b: MyStruct;
            %{
              ...
            %}
            return(b);
          }
    8. Import all the needed constants and struct names
"""

CAIRO_TYPES = { "felt", "EcPoint", "BigInt3" }
REPLACEABLE_TOKEN = "__TOKEN_TO_REPLACE__"

CAIRO_CONSTS = {
    "ADDR_BOUND": "from starkware.starknet.common.storage import ADDR_BOUND"
}

def classify_variables(hint_code):
    """
    classify_varables(String) -> (Dict<String, set>, Dict<String, set>, List<String>)
    return declare_in_main, declare_in_hint_fn, list(consts_to_import)
    Grabs a hint text and classifies all the variables associated with the `ids` structure.
    - declare_in_main: holds all the variables that should be declared in the `main` cairo
        function and that will receive the fuzzer selected values
    - declare_in_hint_fn: holds the variables that are assigned a value inside the hint
    - consts_to_import: holds the cairo constants that are called inside the hint that
        need to be imported form a common library module
    The output dictionaries will also keep track of the variable's fields considering the
    case where a variable is called inside a `pack` function additionally, `pack` can be 
    defined inside the hint or imported from the internal ec point functionality.
    """
    targets = set() 
    ids_nodes = []
    pack_call_nodes = []
    pack_function_nodes = []
    for node in ast.walk(ast.parse(hint_code)):
        if isinstance(node, ast.Assign):
            for assign_node in ast.walk(node):
                if isinstance(assign_node, ast.Attribute) and \
                   isinstance(assign_node.value, ast.Name) and assign_node.value.id == "ids" and \
                   isinstance(assign_node.ctx, ast.Store):
                        targets.add(assign_node.attr)
        elif isinstance(node, ast.Attribute):
            ids_nodes.append(node)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "pack":
            pack_call_nodes.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name == "pack":
            pack_function_nodes.append(node)

    ids_fields = {node.attr:set() for node in ids_nodes if isinstance(node.value, ast.Name) and node.value.id == "ids"} 
    for node in ids_nodes:
        if isinstance(node.value, ast.Attribute) :
            ids_fields[node.value.attr].add(node.attr)

    pack_call_ids = set() 
    for node in pack_call_nodes:
        for arg in node.args:
            if isinstance(arg, ast.Attribute):
                if isinstance(arg.value, ast.Name) and arg.value.id == "ids":
                    pack_call_ids.add(arg.attr)
                elif isinstance(arg.value, ast.Attribute) and arg.value.value.id == "ids":
                    pack_call_ids.add(arg.value.attr)

    def_pack_function = "BigInt3"
    if pack_function_nodes != []:
        z_fields = {b_node.attr for b_node in ast.walk(pack_function_nodes[0]) if isinstance(b_node, ast.Attribute) and b_node.value.id == "z"}
        if z_fields == {"low", "high"}:
            def_pack_function = "SplitNum"

    declare_in_main = {}
    declare_in_hint_fn = {}
    consts_to_import = set() 
    for var_name in ids_fields.keys():
        if var_name in pack_call_ids:
            ids_fields[var_name] = frozenset({def_pack_function}) if def_pack_function == "BigInt3" else frozenset({"low", "high"})
        if ids_fields[var_name] == set():
            ids_fields[var_name] = frozenset({"felt"})

        if var_name in CAIRO_CONSTS:
            consts_to_import.add(var_name)
        elif var_name in targets:
            declare_in_hint_fn[var_name] = frozenset(ids_fields[var_name])
        else:
            declare_in_main[var_name] = frozenset(ids_fields[var_name])
    return declare_in_main, declare_in_hint_fn, list(consts_to_import)

def generate_cairo_hint_program(hint_code):
    """
    generate_cairo_hint_program(String) -> [String]
    Call `classify_varables(hint_code)` and create a cairo program with all the necessary code to run the hint
    code block that was passed as parameter
    """
    declare_in_main, declare_in_hint_fn, consts = classify_variables(hint_code)
    consts_imports = [ import_line for const, import_line in CAIRO_CONSTS.items() if const in consts ]

    all_types = (declare_in_main | declare_in_hint_fn).values()

    import_ecpoint = "from starkware.cairo.common.cairo_secp.ec import EcPoint\n" if any("EcPoint" in types for types in all_types) else ""
    import_bigint3 = "from starkware.cairo.common.cairo_secp.bigint import BigInt3\n" if import_ecpoint != "" or any("BigInt3" in types for types in all_types) else ""

    structs_fields = { f for f in all_types if not f.issubset(CAIRO_TYPES) }
    structs_dict = { v : "MyStruct" + str(i) for (i, v) in enumerate(structs_fields) }

    structs_fmt = "struct {struct_name} {{\n{struct_fields}\n}}\n"
    fields_fmt = "\t{field_name}: felt,"
    
    declared_structs = "\n".join([
        structs_fmt.format(
            struct_name = name,
            struct_fields = "\n".join([fields_fmt.format(field_name=field_name) for field_name in fields])
        )
        for (fields, name) in structs_dict.items() if fields != frozenset({"low", "high"})
    ])

    if frozenset({"low", "high"}) in structs_dict:
        declared_structs += "struct {struct_name} {{\n\tlow: felt,\n\thigh: felt,\n}}".format(struct_name=structs_dict[frozenset({"low", "high"})])

    main_func_fmt = "\nfunc main() {{{variables}\n\thint_func({input_var_names});\n\treturn();\n}}\n"
    main_struct_assignment_fmt = "\n\tlet {var_name} = {struct_name}({assign_fields});"
    main_ecpoint_assignment_fmt = "\n\tlet {var_name} = EcPoint(BigInt3(d0=" + REPLACEABLE_TOKEN + ", d1=" + REPLACEABLE_TOKEN + ", d2=" + REPLACEABLE_TOKEN + "), BigInt3(d0=" + REPLACEABLE_TOKEN + ", d1=" + REPLACEABLE_TOKEN + ", d2=" + REPLACEABLE_TOKEN + "));"
    main_bigint_assignment_fmt = "\n\tlet {var_name} = BigInt3(d0=" + REPLACEABLE_TOKEN + ", d1=" + REPLACEABLE_TOKEN + ", d2=" + REPLACEABLE_TOKEN + ");"
    main_low_high_assignment_fmt = "\n\tlet {var_name} = {struct_name}(low=" + REPLACEABLE_TOKEN + ", high=" + REPLACEABLE_TOKEN + ");"
    main_var_felt_assingment_fmt = "\n\tlet {var_name} =" + REPLACEABLE_TOKEN + ";"

    main_var_assignments = ""
    for name, var_fields in declare_in_main.items():
        if "felt" in var_fields:
            main_var_assignments += main_var_felt_assingment_fmt.format(var_name = name)
        elif "EcPoint" in var_fields:
            main_var_assignments += main_ecpoint_assignment_fmt.format(var_name = name)
        elif "BigInt3" in var_fields:
            main_var_assignments += main_bigint_assignment_fmt.format(var_name = name)
        elif frozenset({"low", "high"}) == var_fields:
            main_var_assignments += main_low_high_assignment_fmt.format(var_name = name, struct_name = structs_dict[frozenset({"low", "high"})])
        else:
            main_var_assignments += main_struct_assignment_fmt.format(
                var_name = name,
                struct_name = structs_dict[var_fields],
                assign_fields = ", ".join([
                    field_name + "=" + REPLACEABLE_TOKEN for field_name in var_fields
                ])
            )

    main_func = main_func_fmt.format(
        variables = main_var_assignments,
        input_var_names = ", ".join([var for var in declare_in_main.keys()])
    )

    hint_func_fmt = "\nfunc hint_func{signature} {{\n\talloc_locals;\n{local_declarations}\n%{{\n{hint}\n%}}\n\treturn({output_return});\n}}\n"
    local_declare_fmt = "\tlocal {res_var_name}: {res_struct};"

    # To extract an element from a set: element = next(iter(a_set))
    input_vars_signatures = ", ".join([
        name + ": " + (next(iter(var_fields)) if var_fields.issubset(CAIRO_TYPES) else structs_dict[var_fields])
        for name, var_fields in declare_in_main.items()
    ])
    output_vars_signatures = ", ".join([
        next(iter(var_fields)) if var_fields.issubset(CAIRO_TYPES) else structs_dict[var_fields]
        for var_fields in all_types
    ])

    signature = "(" + input_vars_signatures + ")"
    if len(all_types) > 1:
        signature += " -> (" + output_vars_signatures + ")"
    elif len(all_types) == 1:
        signature += " -> " + output_vars_signatures

    local_vars = "\n".join([
        local_declare_fmt.format(res_var_name = name, res_struct = next(iter(var_fields)) if var_fields.issubset(CAIRO_TYPES) else structs_dict[var_fields]) for name, var_fields in declare_in_hint_fn.items()
    ])

    hint_func = hint_func_fmt.format(
        signature = signature, 
        local_declarations = local_vars, 
        hint = hint_code,
        output_return = ", ".join([res for res in (declare_in_main | declare_in_hint_fn).keys()])
    )

    return import_ecpoint + import_bigint3 + "\n".join(consts_imports) + "\n" + declared_structs + main_func + hint_func

