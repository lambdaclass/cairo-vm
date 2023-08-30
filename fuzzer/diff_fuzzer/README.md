# Random hint fuzzer

This fuzzer takes a list of pre-selected hints and runs a generated basic program with randomized inputs that uses a random hint from the list.

## To run the fuzzer 

Use the commands:
 - `make fuzzer-deps` to ensure that you have the atheris module and created a python module from `fuzzer/src/py_export.rs` using maturin.
 - `make fuzzer-run-hint-diff` to run the fuzzer.

## The fuzzer
The fuzzer is located in the ***random_hint_fuzzer.py*** file inside the diff_fuzzer folder.

### How does it work?

1. first it selects a random hint with the function `get_random_hint`, it has a list of indexes that represent a hint previously saved in a file within ***/hint_accountant/whitelists/***; Selects a random number between the listed ones and returns the list of lines that correspond to that hint code.
2. Creates a basic program that uses the hint calling the function `generate_cairo_hint_program`, it returns a program with a `REPLACEABLE_TOKEN` constant placed wherever a random value has to be placed.
3. Replace all the constants with random values with the function `generate_limb`, this function returns a value with 70% of provability to be a number within ***range_check_max >> 1 and range_check_max***, with range_check_max being ***"340282366920938463463374607431768211456"*** 15% probability of being a number within ***0 and 10*** and 15% probability of being between ***1 and range_check_max***.
4. Creates a random name for the modified Cairo file and the compiled json one.
5. Write the modified cairo program to a file with the generated ***.cairo*** name.
6. Compile the ***.cairo*** file to get the ***.json*** file.
7. Run the ***.json*** program with the Python original vm implementation and the new Rust one.
8. if both implementations run correctly, use the `check_mem` function to compare that the memories are the same. If one implementation returns an error and the other one runs correctly the fuzzer reports an error, as both implementations should return the same output.

## The program generator 

The program generator is located in the ***cairo_program_gen.py*** file inside the diff_fuzzer folder.

### How does it work?

1. Grab a hint given by the fuzzer.
2. Look for all the `ids.(...)` expressions, make sure to keep track of any ***"="*** to the left or right. Also check for cairo constants
3. Reduce the `ids.(...)` expressions so that all the variables are grouped with their fields.
4. After looking at the `ids.(...)`, import `EcPoint`, `BigInt3` or any cairo constants needed for the hint to run.
5. Create dictionaries and classify the variables from step 3
        - declare_in_main: if ***"="*** was to the ***right***
        - declare_in_hint_fn: if ***"="*** was to the ***left***
6. Create `main` using declare_in_main variables
        
    ```
    func main() {
                let a = MyStruct(field=1, field=2);
                hint_func();
                return();
              }
    ```

7. Create `hint_func` with variables from declare_in_hint_fn as locals
     ```
    hint_func(a: MyStruct) -> (MyStruct) {
            alloc_locals;
            local b: MyStruct;
            %{
              ...
            %}
            return(b);
          }
    ```
    
8. return the entire generated program
