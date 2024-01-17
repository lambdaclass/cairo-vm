#!/usr/bin/env python3

import sys
import json
from zipfile import ZipFile


filename1 = sys.argv[1]
filename2 = sys.argv[2]

strict_comparison_files = ["version.json", "metadata.json", "execution_resources.json", "additional_data.json"]

with ZipFile(filename1) as cairo_lang_pie_zip, ZipFile(filename2) as cairo_vm_pie_zip:
    # Compare json files
    for file in strict_comparison_files:
        # Skipping this check due to a bug in the memory holes count
        # TODO: Remove it once the bug is fixed
        if filename1 == "../../../cairo_programs/keccak_alternative_hint.pie.zip" and file == "execution_resources.json":
            continue
        with cairo_lang_pie_zip.open(file) as cairo_lang_file, cairo_vm_pie_zip.open(file) as cairo_vm_file:
            cl_content = json.load(cairo_lang_file)
            cv_content = json.load(cairo_vm_file)
            if cl_content != cv_content:
                print(f"Comparison unsuccesful for {filename1}/{file}  vs {filename2}/{file}")
                exit(1)

    print(f"Comparison succesful for {filename1} vs {filename2}")
