#!/usr/bin/env python3

import sys
import json
from zipfile import ZipFile


filename1 = sys.argv[1]
filename2 = sys.argv[2]

with ZipFile(filename1) as cairo_lang_pie_zip, ZipFile(filename2) as cairo_vm_pie_zip:
    with cairo_lang_pie_zip.open('version.json') as cl_verison_file, cairo_vm_pie_zip.open('version.json') as cv_verison_file:
        cl_version = json.load(cl_verison_file)
        cv_version = json.load(cv_verison_file)
        if cl_version == cv_verison_file:
            print(f"Comparison succesful for {filename1}/version.json vs {filename2}/version.json")
        else:
            print(f"Comparison unsuccesful for {filename1}/version.json  vs {filename2}/version.json")
            exit(1)

