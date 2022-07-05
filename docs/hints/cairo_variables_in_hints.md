# Accessing Cairo variables in hints

When there is a hint embedded in the cairo language, the cairo compiler creates a scope for the hint in the json file, inside the `hints` key. Inside this scope, there is a key `flow_tracking_data` that at the same time has a key `reference_ids`, that maps every variable used in the hint with an id. Example:

The corresponding scope for the hint

```
func assert_not_equal(a, b):
    %{
        from starkware.cairo.lang.vm.relocatable import RelocatableValue
        both_ints = isinstance(ids.a, int) and isinstance(ids.b, int)
        both_relocatable = (
            isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and
            ids.a.segment_index == ids.b.segment_index)
        assert both_ints or both_relocatable, \
            f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'
        assert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'
    %}
    if a == b:
        # If a == b, add an unsatisfiable requirement.
        a = a + 1
    end

    return ()
end
```
in the json file is

```
    "hints": {
        "0": [
            {
                "accessible_scopes": [
                    "__main__",
                    "__main__.assert_not_equal"
                ],
                "code": "from starkware.cairo.lang.vm.relocatable import RelocatableValue\nboth_ints = isinstance(ids.a, int) and isinstance(ids.b, int)\nboth_relocatable = (\n    isinstance(ids.a, RelocatableValue) and isinstance(ids.b, RelocatableValue) and\n    ids.a.segment_index == ids.b.segment_index)\nassert both_ints or both_relocatable, \\\n    f'assert_not_equal failed: non-comparable values: {ids.a}, {ids.b}.'\nassert (ids.a - ids.b) % PRIME != 0, f'assert_not_equal failed: {ids.a} = {ids.b}.'",
                "flow_tracking_data": {
                    "ap_tracking": {
                        "group": 0,
                        "offset": 0
                    },
                    "reference_ids": {
                        "__main__.assert_not_equal.a": 0,
                        "__main__.assert_not_equal.b": 1
                    }
                }
            }
        ]
    },
```

So here the variables `a` and `b` are mapped to 0 and 1, accordingly.

There is another key, `reference_manager`, that looks like this:

```
    "reference_manager": {
        "references": [
            {
                "ap_tracking_data": {
                    "group": 0,
                    "offset": 0
                },
                "pc": 0,
                "value": "[cast(fp + (-4), felt*)]"
            },
            {
                "ap_tracking_data": {
                    "group": 0,
                    "offset": 0
                },
                "pc": 0,
                "value": "[cast(fp + (-3), felt*)]"
            },
            {
                "ap_tracking_data": {
                    "group": 0,
                    "offset": 1
                },
                "pc": 1,
                "value": "[cast(ap + (-1), felt*)]"
            }
        ]
    }
```

I believe that the id corresponding to each variable corresponds to the index of the list of references inside the reference manager. If this is the case, we would know where in memory each reference points to (for example, `fp -4` for `a` and `fp - 3` for `b`)





