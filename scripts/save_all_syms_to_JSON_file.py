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
                sym_name = symbol.name
                if len(sym_name) < 1:
                    continue
                else:
                     symbols.append(symbol.name)

    return symbols


def get_required_shared_objects(elf_file):
    shared_objects_list = []
    dynamic_section = elf_file.get_section_by_name(".dynamic")
    if not dynamic_section:
        return None

    for tag in dynamic_section.iter_tags():
        if tag.entry.d_tag == "DT_NEEDED":
            shared_objects_list.append(tag.needed)

    return shared_objects_list


def create_JSON_record(path, imports, exports, symtab_syms, required_libs):
    if required_libs is not None:
        if len(required_libs) > 0:
            required_libs = sorted(required_libs)
    
    if len(imports) > 0:
        imports = sorted(imports)

    if len(exports) > 0:
        exports = sorted(exports)

    if len(symtab_syms) > 0:
        symtab_syms = sorted(symtab_syms)


    record_dict = {
        "file_name": str(path.name),
        "file_path": str(path),
        "required_libraries": required_libs,
        "imported_symbols": imports,
        "exported_symbols": exports,
        "symtab_symbols": symtab_syms
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
        required_shared_objects = get_required_shared_objects(elf_file)

        json_file_record = create_JSON_record(filepath, imported_syms_list, exported_syms_list, symtab_syms_list, required_shared_objects)

    return json_file_record


def main(args):
    root_path = pathlib.Path(args.root_path)
    if not root_path.is_dir():
        logging.info(f"[-] '{args.root_path}' is not a directory.")
        exit(-1)

    with open(args.output_path, "w") as f:
        for file_path in pathlib.Path(root_path).rglob("*"):
            if not pathlib.Path.is_file(file_path):
                 continue

            json_record = parse_file(file_path)
            #print(json_record)
            if json_record is None:
                continue
            else:
                f.write(json_record + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root-path", help="Root directory of file system search", required=True)
    parser.add_argument("--output-path", help="Path to save JSON file to", required=True)
    args = parser.parse_args()

    main(args)