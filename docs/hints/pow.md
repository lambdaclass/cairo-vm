# pow.cairo functions
A summary of pow.cairo functions, hints used and function dependencies 

https://github.com/starkware-libs/cairo-lang/blob/167b28bcd940fd25ea3816204fa882a0b0a49603/src/starkware/cairo/common/pow.cairo


## func pow:
* Status: 
* Assignee:
* Hints:

```
%{ ids.locs.bit = (ids.prev_locs.exp % PRIME) & 1 %}
```
* Depends on functions: 
    * `assert_le`
    * `get_ap`
    * `get_fp_and_pc`



