#!/usr/bin/env python3

import json
import pathlib
import argparse
import logging
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.common.exceptions import ELFError


logging.basicConfig(filename="/tmp/elf-symbol-search.log",
                    level=logging.INFO)


PAD = 20

# If dynamic symbol["st_shndx"] == "SH_UNDEF", it is an symbol.
# Else, it is an export.
def get_dynamic_symbols(elf_file):
    imports = []
    exports = []
    for section in elf_file.iter_sections():
        if isinstance(section, SymbolTableSection) and section['sh_type'] == 'SHT_DYNSYM':
            for symbol in section.iter_symbols():
                sym_name = symbol.name

                if sym_name is None or len(sym_name) == 0:
                    continue

                shndx = symbol["st_shndx"]

                if shndx == "SHN_UNDEF":
                    imports.append(sym_name)
                else:
                    exports.append(sym_name)

    return imports, exports


def get_symtab_symbols(elf_file):
    symbols = []
    for section in elf_file.iter_sections():
        if isinstance(section, SymbolTableSection) and section['sh_type'] == 'SHT_SYMTAB':
            for symbol in section.iter_symbols():
                symbols.append(symbol.name)

    return symbols


def create_JSON_record(path, imports, exports, symtab_syms):
    record_dict = {
        "file name": str(path.name),
        "file path": str(path),
        "imported symbols": sorted(imports),
        "exported symbols": sorted(exports),
        "symtab symbols": sorted(symtab_syms)
    }

    return json.dumps(record_dict)


def parse_file(filepath):
    with open(filepath, "rb") as f:
        try:
            elf_file = ELFFile(f)
        except ELFError:
            return
        except Exception as e:
            logging.error(f"[!] ERROR: unexpected error parsing '{f.name}'")
            return

        imported_syms_list, exported_syms_list = get_dynamic_symbols(elf_file)
        symtab_syms_list = get_symtab_symbols(elf_file)
        json_file_record = create_JSON_record(filepath, imported_syms_list, exported_syms_list, symtab_syms_list)

    return json_file_record


def main(args):
    root_path = pathlib.Path(args.root_path)
    if not root_path.is_dir():
        logging.info(f"[-] '{args.root_path}' is not a directory.")
        exit(-1)

    for file_path in pathlib.Path(root_path).rglob("*"):
        if not pathlib.Path.is_file(file_path):
            continue

        json_record = parse_file(file_path)
        print(json_record)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root-path", help="Root directory of file system search", required=True)
    args = parser.parse_args()

    main(args)