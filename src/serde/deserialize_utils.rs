use crate::bigint;
use crate::serde::deserialize_program::ValueAddress;
use crate::types::instruction::Register;
use nom::{
    branch::alt,
    bytes::{complete::take_until, streaming::tag},
    character::complete::digit1,
    combinator::{map_res, opt, value},
    error::{ErrorKind, ParseError},
    sequence::{delimited, tuple},
    IResult,
};
use num_bigint::{BigInt, ParseBigIntError};
use num_integer::Integer;
use num_traits::FromPrimitive;
use parse_hyperlinks::take_until_unbalanced;
use std::fmt;
use std::num::ParseIntError;
use std::str::FromStr;

#[derive(Debug, PartialEq)]
pub enum ReferenceParseError {
    IntError(ParseIntError),
    BigIntError(ParseBigIntError),
    InvalidStringError(String),
}

impl fmt::Display for ReferenceParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ReferenceParseError::IntError(error) => {
                write!(f, "Int parsing error: ")?;
                error.fmt(f)
            }
            ReferenceParseError::BigIntError(error) => {
                write!(f, "BigInt parsing error: ")?;
                error.fmt(f)
            }
            ReferenceParseError::InvalidStringError(error) => {
                write!(f, "Invalid reference string error: ")?;
                error.fmt(f)
            }
        }
    }
}

// Checks if the hex string has an odd length.
// If that is the case, prepends '0' to it.
pub fn maybe_add_padding(mut hex: String) -> String {
    if hex.len().is_odd() {
        hex.insert(0, '0');
        return hex;
    }
    hex
}

/* NOM PARSERS */

// Checks if the input has outer brackets. This is used to set
// the `dereference` field of ValueAddress.
fn outer_brackets(input: &str) -> IResult<&str, bool> {
    opt(delimited(
        tag("["),
        take_until_unbalanced('[', ']'),
        tag("]"),
    ))(input)
    .map(|(rem_input, res_opt)| {
        if let Some(res) = res_opt {
            (res, true)
        } else {
            (rem_input, false)
        }
    })
}

// Removes the cast string and parenthesis from the value.
fn take_cast(input: &str) -> IResult<&str, &str> {
    let (rem_input, _) = tag("cast")(input)?;
    delimited(tag("("), take_until_unbalanced('(', ')'), tag(")"))(rem_input)
        .map(|(rem_input, res)| (res, rem_input))
}

// Returns the first argument of the cast function from the value.
fn take_cast_first_arg(input: &str) -> IResult<&str, &str> {
    let (rem_input, _) = take_cast(input)?;

    take_until(",")(rem_input).map(|(rem_input, res)| (res, rem_input))
}

fn register(input: &str) -> IResult<&str, Register> {
    alt((
        value(Register::AP, tag("ap")),
        value(Register::FP, tag("fp")),
    ))(input)
}

fn offset(input: &str) -> IResult<&str, i32> {
    if input.eq("") {
        return Ok(("", 0));
    }

    let (rem_input, _) = opt(alt((tag(" + "), tag(" - "))))(input)?;
    let (rem_input, num_opt) = opt(delimited(tag("("), take_until(")"), tag(")")))(rem_input)?;

    if let Some(num) = num_opt {
        let parsed_num: i32 = match num.parse() {
            Ok(parsed_num) => parsed_num,
            Err(_) => {
                return Err(nom::Err::Error(ParseError::from_error_kind(
                    num,
                    ErrorKind::MapRes,
                )))
            }
        };

        Ok((rem_input, parsed_num))
    } else {
        map_res(digit1, i32::from_str)(rem_input)
    }
}

fn register_and_offset(input: &str) -> IResult<&str, (Register, i32)> {
    let (rem_input, reg) = register(input)?;
    let (rem_input, offset) = offset(rem_input)?;

    Ok((rem_input, (reg, offset)))
}

fn inner_dereference(input: &str) -> IResult<&str, (bool, Register, i32)> {
    map_res(
        delimited(tag("["), take_until("]"), tag("]")),
        register_and_offset,
    )(input)
    .map(|(rem_input, res)| {
        let (_, (register, offset)) = res;

        (rem_input, (true, register, offset))
    })
}

fn no_inner_dereference(input: &str) -> IResult<&str, (bool, Register, i32)> {
    let (rem_input, (register, offset)) = register_and_offset(input)?;
    Ok((rem_input, (false, register, offset)))
}

pub fn parse_value(input: &str) -> IResult<&str, ValueAddress> {
    let (rem_input, (dereference, _, inner_deref, offs_or_imm)) = tuple((
        outer_brackets,
        take_cast_first_arg,
        opt(alt((inner_dereference, no_inner_dereference))),
        opt(offset),
    ))(input)?;

    // check if there was any register and offset to be parsed
    let (inner_deref, reg, offs1) = if let Some((inner_deref, reg, offs1)) = inner_deref {
        (inner_deref, Some(reg), offs1)
    } else {
        (false, None, 0)
    };

    // check if there is a second offset or immediate value
    let offset_or_immediate = if let Some(offset_or_immediate) = offs_or_imm {
        offset_or_immediate
    } else {
        0
    };

    let value_address = if dereference {
        ValueAddress {
            register: reg,
            offset1: offs1,
            offset2: offset_or_immediate,
            immediate: None,
            dereference,
            inner_dereference: inner_deref,
        }
    } else {
        ValueAddress {
            register: reg,
            offset1: offs1,
            offset2: 0,
            immediate: Some(bigint!(offset_or_immediate)),
            dereference,
            inner_dereference: inner_deref,
        }
    };

    Ok((rem_input, value_address))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bigint;

    #[test]
    fn outer_brackets_test() {
        let deref_value = "[cast([fp])]";
        let parsed_deref = outer_brackets(deref_value);
        assert_eq!(parsed_deref, Ok(("cast([fp])", true)));

        let ref_value = "cast([fp])";
        let parsed_ref = outer_brackets(ref_value);
        assert_eq!(parsed_ref, Ok(("cast([fp])", false)));
    }

    #[test]
    fn take_cast_test() {
        let value = "cast([fp + (-1)], felt*)";
        let parsed = take_cast(value);
        assert_eq!(parsed, Ok(("[fp + (-1)], felt*", "")));
    }

    #[test]
    fn take_cast_first_arg_test() {
        let value = "cast([fp + (-1)] + (-1), felt*)";
        let parsed = take_cast_first_arg(value);

        assert_eq!(parsed, Ok(("[fp + (-1)] + (-1)", ", felt*")));
    }

    #[test]
    fn parse_register_test() {
        let value = "fp + (-1)";
        let parsed = register(value);

        assert_eq!(parsed, Ok((" + (-1)", Register::FP)));
    }

    #[test]
    fn parse_offset_test() {
        let value_1 = " + (-1)";
        let parsed_1 = offset(value_1);
        assert_eq!(parsed_1, Ok(("", -1_i32)));

        let value_2 = " + 1";
        let parsed_2 = offset(value_2);
        assert_eq!(parsed_2, Ok(("", 1_i32)));
    }

    #[test]
    fn parse_register_and_offset_test() {
        let value_1 = "fp + 1";
        let parsed_1 = register_and_offset(value_1);

        assert_eq!(parsed_1, Ok(("", (Register::FP, 1_i32))));

        let value_2 = "ap + (-1)";
        let parsed_2 = register_and_offset(value_2);

        assert_eq!(parsed_2, Ok(("", (Register::AP, -1_i32))));
    }

    #[test]
    fn parse_inner_dereference_test() {
        let value = "[fp + (-1)] + 2";
        let parsed = inner_dereference(value);

        assert_eq!(parsed, Ok((" + 2", (true, Register::FP, -1_i32))));
    }

    #[test]
    fn parse_no_inner_dereference_test() {
        let value = "ap + 3";
        let parsed = no_inner_dereference(value);

        assert_eq!(parsed, Ok(("", (false, Register::AP, 3_i32))));
    }

    #[test]
    fn parse_value_with_inner_dereference_test() {
        let value = "[cast([fp + (-1)] + 2, felt*)]";
        let parsed = parse_value(value);

        assert_eq!(
            parsed,
            Ok((
                "",
                ValueAddress {
                    register: Some(Register::FP),
                    offset1: -1,
                    offset2: 2,
                    immediate: None,
                    dereference: true,
                    inner_dereference: true
                }
            ))
        );
    }

    #[test]
    fn parse_value_with_no_inner_dereference_test() {
        let value = "cast(ap + 2, felt*)";
        let parsed = parse_value(value);

        assert_eq!(
            parsed,
            Ok((
                "",
                ValueAddress {
                    register: Some(Register::AP),
                    offset1: 2,
                    offset2: 0,
                    immediate: Some(bigint!(0)),
                    dereference: false,
                    inner_dereference: false
                }
            ))
        );
    }

    #[test]
    fn parse_value_with_no_register_test() {
        let value = "cast(825323, felt*)";
        let parsed = parse_value(value);
        assert_eq!(
            parsed,
            Ok((
                "",
                ValueAddress {
                    register: None,
                    offset1: 0,
                    offset2: 0,
                    immediate: Some(bigint!(825323)),
                    dereference: false,
                    inner_dereference: false
                }
            ))
        );
    }

    #[test]
    fn parse_value_with_no_inner_deref_and_two_offsets() {
        let value = "[cast(ap - 0 + (-1), felt*)]";
        let parsed = parse_value(value);

        assert_eq!(
            parsed,
            Ok((
                "",
                ValueAddress {
                    register: Some(Register::AP),
                    offset1: 0,
                    offset2: -1,
                    immediate: None,
                    dereference: true,
                    inner_dereference: false
                }
            ))
        );
    }
}
