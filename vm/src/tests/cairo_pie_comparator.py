#!/usr/bin/env python3

import sys
import json
from typing import Any
from zipfile import ZipFile
import memory_comparator

filename1 = sys.argv[1]
filename2 = sys.argv[2]

json_files = ["version.json", "metadata.json", "execution_resources.json", "additional_data.json"]


def filter_null_values(content: Any) -> Any:
    if isinstance(content, dict):
        return {k: v for k, v in content.items() if v is not None}

    return content


def json_contents_are_equivalent(cl: Any, cv: Any) -> bool:
    """
    Compares the two JSON contents. and returns whether they are equivalent.
    Contents are considered equivalent if they are equal or if some keys have null values in one
    content and are just missing from the other.
    """

    return filter_null_values(cl) == filter_null_values(cv)


with ZipFile(filename1) as cairo_lang_pie_zip, ZipFile(filename2) as cairo_vm_pie_zip:
    # Compare json files
    for file in json_files:
        with cairo_lang_pie_zip.open(file) as cairo_lang_file, cairo_vm_pie_zip.open(file) as cairo_vm_file:
            cl_content = json.load(cairo_lang_file)
            cv_content = json.load(cairo_vm_file)
            if not json_contents_are_equivalent(cl_content, cv_content):
                print(f"Comparison unsuccesful for {filename1}/{file}  vs {filename2}/{file}")
                exit(1)

    # Compare binary files
    with cairo_lang_pie_zip.open("memory.bin", 'r') as f1, cairo_vm_pie_zip.open("memory.bin", 'r') as f2:
        memory_comparator.compare_memory_file_contents(f1.read(), f2.read())

    print(f"Comparison succesful for {filename1} vs {filename2}")
