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
FUNC_PARAM_EX = "var_in_func"
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

def process_line(line, functions):
    """
    process_line(String, {String, {String}}]) -> [ [EX_TYPE_CONST, ..., EX_TYPE_CONST, [String]] ]
    Return the expression type of the line, adding relevant information if the an assignment was made or if the
    variable in the line is inside a `pack(var, PRIME)` function. Return the variable as [name, fields...]
    """
    if get_expr_type(line) == ASSIGN_EX_TYPE:
        equals_pos = line.rfind("=")
        variables = [ clean_trailing(v) for v in line.split() if "ids." in v ]
        return [
            [ASSIGN_EX_TYPE, LEFT if line.find(v) < equals_pos else RIGHT] + \
            get_function_ex(line, v, functions) + \
            [v[v.find("ids.") + 4:].split(".")] \
            for v in variables 
        ]
    else:
        return [
            [OTHER_EX_TYPE] + \
            get_function_ex(line, v, functions) + \
            [clean_trailing(v)[v.find("ids.") + 4:].split(".")] 
            for v in line.split() if "ids." in v 
        ]

def get_function_ex(line, variable, functions):
    """
    get_function_ex(String, String, {String, {String}}) -> [ EX_TYPE_CONST ]
    """
    if "pack" not in functions.keys():
        if var_in_func(line, variable, "pack"):
            return [PACK_PARAM_EX]
    for func_name in functions.keys():
        if var_in_func(line, variable, func_name):
            return [FUNC_PARAM_EX, functions[func_name]]
    return []

def process_func(function):
    """
    process_func(String) -> (String, {String})
    Get a function block and transform it into a tuple: (function name, fields of variable in block)
    The current implementation is tied to the following type of function:
        def pack(z, num: int)
                 ^ Value with fields
    """
    signature = function[0]
    after_def_pos = signature.find("def ") + 4
    function_name = signature[after_def_pos: signature.find("(", after_def_pos)].strip()
    # Get the first variable name inside the function signature
    variable = signature[signature.find("(") + 1:signature.find(")")].split(",")[0].strip()
    body = (line for line in function[1:] if variable in line)
    fields = set()
    for line in body:
        for token in line.split():
            if variable + "." in token:
                field = clean_trailing(token[(token.find(variable + ".") + len(variable + ".")):])
                fields.add(field)
    
    return (function_name, frozenset(fields))

         
def clean_trailing(var):
    """
    clean_trailing(String) -> String
    Make sure variable doesn't end with any non-alfanumeric characters
    """
    i = 1
    while not var[len(var) - i].isalnum():
        i += 1
    return var[:len(var) - i + 1]

def var_in_func(line, var, func_name):
    """
    var_in_func(String, String, String) -> bool
    Check if a variable is inside a function call.
    This function expects a stripped variable, without the `ids.` prefix.
    Also, the current implemenation doesn't deal with parenthesis inside the function call
    """
    if func_name not in line:
        return False
    # Assuming there is no inner parenthesis in func(...)
    func_start = line.find(func_name)
    func_end = line.find(")", func_start)
    func_call = line[func_start:func_end]
    return var in func_call 

def variables_with_context(hint_lines):
    functions = {}
    variables = []
    total_lines = len(hint_lines)
    line_num = 0
    line = lambda: hint_lines[line_num]
    indentation = lambda: len(hint_lines[line_num]) - len(hint_lines[line_num].lstrip())

    while line_num < total_lines:
        if "def" in line():
            signature_body = [line()]
            line_num += 1
            body_indent = current_indent = indentation()
            while current_indent >= body_indent:
                signature_body.append(line())
                line_num += 1
                current_indent = indentation()
            functions.update([process_func(signature_body)])
        if "ids." in line():
            variables += process_line(line(), functions)
        line_num += 1
        
    return variables


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
    expressions = variables_with_context([line for line in hint_code.split("\n") if "#" not in line])

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

        if FUNC_PARAM_EX in expression_type:
            variable_type = expression_type[expression_type.index(FUNC_PARAM_EX) + 1]

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

