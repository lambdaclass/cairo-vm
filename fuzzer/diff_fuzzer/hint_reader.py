import re

def load_hints():
    # Match any string with the pattern:
    # r"# hint code
    #     hint code
    #     ..."#;
    # ?: makes sure that the match stops at first "#; aparition
    raw_str_pattern = re.compile('r#"(.*?)"#;', re.DOTALL)
    # Match any of the string options
    # variable << variable
    # variable << number literal
    # number literal << variable
    # number literal << number literal
    shift_right_pattern = "[\d+|\w+]\s*<<\s*[\d+|\w+]"
    # Match any hint with SECP_P present
    secp_p_pattern = "from.*import.*SECP_P|SECP_P\s*="
    filter_pattern = re.compile(f"{shift_right_pattern}|{secp_p_pattern}")
    with open("../../vm/src/hint_processor/builtin_hint_processor/hint_code.rs", "r") as f:
        hints_code = f.read()

    return [hint_code.group(1) for hint_code in raw_str_pattern.finditer(hints_code) if filter_pattern.search(hint_code.group(1))]

