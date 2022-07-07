# signature.cairo functions
A summary of signature.cairo functions, hints used and function dependencies 

https://github.com/starkware-libs/cairo-lang/blob/167b28bcd940fd25ea3816204fa882a0b0a49603/src/starkware/cairo/common/signature.cairo

## func verify_ecdsa_signature:
* Status:
* Assignee:
* Hints:

```
%{ ecdsa_builtin.add_signature(ids.ecdsa_ptr.address_, (ids.signature_r, ids.signature_s)) %}
```
* Depends of functions: None