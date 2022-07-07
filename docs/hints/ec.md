# ec.cairo functions
A summary of ec.cairo functions, hints used and function dependencies 

https://github.com/starkware-libs/cairo-lang/blob/167b28bcd940fd25ea3816204fa882a0b0a49603/src/starkware/cairo/common/ec.cairo

## func assert_on_curve:
* Hints: None
* Depends on functions: None

## func ec_double:
* Hints: None
* Depends on functions: None

## func ec_add:
* Hints: None
* Depends on functions:
    * `ec_double`

## func ec_op:
* Hints:
```
    %{
        from starkware.crypto.signature.signature import ALPHA, BETA, FIELD_PRIME
        from starkware.python.math_utils import random_ec_point
        def to_bytes(n):
            return n.to_bytes(256, "little")

        # Define a seed for random_ec_point that's dependent on all the input, so that:
        #   (1) The added point s is deterministic.
        #   (2) It's hard to choose inputs for which the builtin will fail.
        seed = b"".join(map(to_bytes, [ids.p.x, ids.p.y, ids.m, ids.q.x, ids.q.y]))
        ids.s.x, ids.s.y = random_ec_point(FIELD_PRIME, ALPHA, BETA, seed)
    %}
```
* Depends on functions:
    * `ec_add`
