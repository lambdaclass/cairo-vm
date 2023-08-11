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

ASSIGN_EX_TYPE = "assign"
LEFT = "left"
RIGHT = "right"
OTHER_EX_TYPE = "other"
PACK_PARAM_EX = "var_in_pack"
CAIRO_TYPES = { "felt", "EcPoint", "BigInt3" }
REPLACEABLE_TOKEN = "__TOKEN_TO_REPLACE__"

def get_expr_type(line):
    """
    Check if the line has an `==` operator and classify it as a `OTHER_EX_TYPE` expression, this is done before
    it looks for the `=` operator, wich is assumed to be an `ASSIGN_EX_TYPE` expression
    """
    if any(token in line for token in ["==", "assert"]):
        return OTHER_EX_TYPE
    elif "=" in line:
        return ASSIGN_EX_TYPE
    else:
        return OTHER_EX_TYPE

def process_line(line):
    """
    process_line(String) -> [ [EX_TYPE_CONST, ..., EX_TYPE_CONST, [String]] ]
    Return the expression type of the line, adding relevant information if the an assignment was made or if the
    variable in the line is inside a `pack(var, PRIME)` function. Return the variable as [name, fields...]
    """
    if get_expr_type(line) == ASSIGN_EX_TYPE:
        equals_pos = line.rfind("=")
        variables = [ clean_trailing(v) for v in line.split() if "ids." in v ]
        return [
            [ASSIGN_EX_TYPE, LEFT if line.find(v) < equals_pos else RIGHT] + \
            ([PACK_PARAM_EX] if var_in_pack(line, v) else []) + \
            [v[v.find("ids.") + 4:].split(".")] \
            for v in variables 
        ]
    else:
        return [
            [OTHER_EX_TYPE] + \
            ([PACK_PARAM_EX] if var_in_pack(line, v) else []) + \
            [clean_trailing(v)[v.find("ids.") + 4:].split(".")] 
            for v in line.split() if "ids." in v 
        ]
         
def clean_trailing(var):
    """
    clean_trailing(String) -> String
    Make sure variable doesn't end with any non-alfanumeric characters
    """
    i = 1
    while not var[len(var) - i].isalnum():
        i += 1
    return var[:len(var) - i + 1]

def var_in_pack(line, var):
    """
    var_in_pack(String, String) -> bool
    Check if a variable is inside a pack(variable, PRIME) call.
    This function expects a stripped variable, without the `ids.` prefix.
    Also, the current implemenation doesn't deal with parenthesis inside the `pack` call
    """
    if "pack(" not in line:
        return False
    # Assuming there is no inner parenthesis in pack(...)
    pack_start = line.find("pack(")
    pack_end = line.find(")", pack_start)
    return var in line[pack_start:pack_end]
     
def classify_variables(hint_code):
    """
    classify_varables(String) -> (Dict<String, set>, Dict<String, set>)
    Takes a hint code block and extract all the variables with the `ids.` prefix, classifying each one into
    dictionaries: varables to declare in the main function and variables to declare in the hint function.
    Then if the variable has fields, annotate them in the corresponding dictionary, otherwise it's normally
    considered a felt execpt for the special case: being passed as an argument to a `pack(variable, PRIME)`
    function.
    """
    declare_in_main = dict()
    declare_in_hint_fn = dict()

    # Get all lines with the `ids.` identifier and then dump them into an array of expressions (other or assign)
    # Doesn't consider lines with a comment on them
    # expressions: [ [EX_TYPE_CONSTs..., [String]], ... ]
    expressions = []
    for line in hint_code.split("\n"):
        if "ids." in line and "#" not in line:
            expressions += process_line(line)

    # Create a var_name: { set of fields or cairo type } pair to insert in one of the output dictionaries
    for expr in expressions:
        expression_type = expr[:-1]
        variable_name = expr[-1][0]
        variable_type = expr[-1][1:]

        # Overrite fields with EcPoint or BigInt3 if necessary
        if PACK_PARAM_EX in expression_type:
            if any(ec_point_fields in variable_type for ec_point_fields in ["x", "y"]):
                variable_type = {"EcPoint"}
            else:
                variable_type = {"BigInt3"}

        dict_to_insert = declare_in_main
        if ASSIGN_EX_TYPE in expression_type:
            if RIGHT in expression_type:
                dict_to_insert = declare_in_main
            if LEFT in expression_type:
                dict_to_insert = declare_in_hint_fn

        if variable_type == []: variable_type = {"felt"}

        # Make sure not to lose info if the variable already had an EcPoint or BigInt3 type
        if variable_name in dict_to_insert and not dict_to_insert[variable_name].issubset({"EcPoint", "BigInt3"}):
            dict_to_insert[variable_name].update(variable_type)
        elif variable_name not in dict_to_insert:
            dict_to_insert[variable_name] = set(variable_type)

    # Freeze sets
    declare_in_main.update((k, frozenset(v)) for (k, v) in declare_in_main.items())
    declare_in_hint_fn.update((k, frozenset(v)) for (k, v) in declare_in_hint_fn.items())
    return declare_in_main, declare_in_hint_fn

def generate_cairo_hint_program(hint_code):
    """
    generate_cairo_hint_program(String) -> [String]
    Call `classify_varables(hint_code)` and create a cairo program with all the necessary code to run the hint
    code block that was passed as parameter
    """
    declare_in_main, declare_in_hint_fn = classify_variables(hint_code)

    all_types = (declare_in_main | declare_in_hint_fn).values()

    import_ecpoint = "from starkware.cairo.common.cairo_secp.ec import EcPoint\n" if any("EcPoint" in types for types in all_types) else ""
    import_bigint3 = "from starkware.cairo.common.cairo_secp.bigint import BigInt3\n" if import_ecpoint != "" or any("BigInt3" in types for types in all_types) else ""

    structs_fields = { f for f in all_types if not f.issubset(CAIRO_TYPES) }
    structs_dict = { v : "MyStruct" + str(i) for (i, v) in enumerate(structs_fields) }

    structs_fmt = "struct {struct_name} {{\n{struct_fields}\n}}"
    fields_fmt = "\t{field_name}: felt,"
    
    declared_structs = "\n".join([
        structs_fmt.format(
            struct_name = name,
            struct_fields = "\n".join([fields_fmt.format(field_name=field_name) for field_name in fields])
        )
        for (fields, name) in structs_dict.items()
    ])

    main_func_fmt = "\nfunc main() {{{variables}\n\thint_func({input_var_names});\n\treturn();\n}}\n"
    main_struct_assignment_fmt = "\n\tlet {var_name} = {struct_name}({assign_fields});"
    main_ecpoint_assignment_fmt = "\n\tlet {var_name} = EcPoint(BigInt3(d0=" + REPLACEABLE_TOKEN + ", d1=" + REPLACEABLE_TOKEN + ", d2=" + REPLACEABLE_TOKEN + "), BigInt3(d0=" + REPLACEABLE_TOKEN + ", d1=" + REPLACEABLE_TOKEN + ", d2=" + REPLACEABLE_TOKEN + "));"
    main_bigint_assignment_fmt = "\n\tlet {var_name} = BigInt3(d0=" + REPLACEABLE_TOKEN + ", d1=" + REPLACEABLE_TOKEN + ", d2=" + REPLACEABLE_TOKEN + ");"
    main_var_felt_assingment_fmt = "\n\tlet {var_name} =" + REPLACEABLE_TOKEN + ";"

    main_var_assignments = ""
    for name, var_fields in declare_in_main.items():
        if "felt" in var_fields:
            main_var_assignments += main_var_felt_assingment_fmt.format(var_name = name)
        elif "EcPoint" in var_fields:
            main_var_assignments += main_ecpoint_assignment_fmt.format(var_name = name)
        elif "BigInt3" in var_fields:
            main_var_assignments += main_bigint_assignment_fmt.format(var_name = name)
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

    hint_input_var_fmt = "{var_name}: {struct_name}"
    local_declare_fmt = "\tlocal {res_var_name}: {res_struct};"

    signature = "(" + \
        ", ".join([
            hint_input_var_fmt.format(var_name = name, struct_name = next(iter(var_fields)) if var_fields.issubset(CAIRO_TYPES) else structs_dict[var_fields]) for name, var_fields in declare_in_main.items()
        ]) + \
        ") -> (" + \
        ", ".join([next(iter(var_fields)) if var_fields.issubset(CAIRO_TYPES) else structs_dict[var_fields] for var_fields in (declare_in_main | declare_in_hint_fn).values()]) + \
        ")"

    local_vars = "\n".join([
        local_declare_fmt.format(res_var_name = name, res_struct = next(iter(var_fields)) if var_fields.issubset(CAIRO_TYPES) else structs_dict[var_fields]) for name, var_fields in declare_in_hint_fn.items()
    ])

    hint_func = hint_func_fmt.format(
        signature = signature, 
        local_declarations = local_vars, 
        hint = hint_code,
        output_return = ", ".join([res for res in (declare_in_main | declare_in_hint_fn).keys()])
    )

    return import_ecpoint + import_bigint3 + declared_structs + main_func + hint_func

