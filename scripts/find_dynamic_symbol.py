#!/usr/bin/env python3

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
def search_for_dynamic_symbol(file_handle, elf_file, symbol_name, strict):
    for section in elf_file.iter_sections():
        if isinstance(section, SymbolTableSection) and section['sh_type'] == 'SHT_DYNSYM':
            for symbol in section.iter_symbols():
                sym_name = symbol.name

                if sym_name is None or len(sym_name) == 0:
                    continue

                shndx = symbol["st_shndx"]

                if shndx == "SHN_UNDEF":
                    if strict:
                        if symbol_name == sym_name:
                            logging.info(f" [+][IMPORT]: {sym_name}: {file_handle.name}")
                    else:
                        if symbol_name in sym_name:
                            logging.info(f" [+][IMPORT]: {sym_name}: {file_handle.name}")
                else:
                    if strict:
                        if symbol_name == sym_name:
                            logging.info(f" [-][EXPORT]: {sym_name}: {file_handle.name}")
                    else:
                        if symbol_name in sym_name:
                            logging.info(f" [-][EXPORT]: {sym_name}: {file_handle.name}")


def parse_file(filepath, symbol_name, strict):
    with open(filepath, "rb") as f:
        try:
            elf_file = ELFFile(f)
        except ELFError:
            return
        except Exception as e:
            logging.error(f"[!] ERROR: unexpected error parsing '{f.name}'")
            return

        search_for_dynamic_symbol(f, elf_file, symbol_name, strict)        


def main(args):
    root_path = pathlib.Path(args.root_path)
    if not root_path.is_dir():
        logging.info(f"[-] '{args.root_path}' is not a directory.")
        exit(-1)

    for file_path in pathlib.Path(root_path).rglob("*"):
        if not pathlib.Path.is_file(file_path):
            continue

        parse_file(file_path, args.symbol_name, args.strict)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root-path", help="Root directory of file system search", required=True)
    parser.add_argument("--symbol-name", help="Name of dynamic symbol to search for", required=True)
    parser.add_argument("--strict", help="Only exact matches to symbol name argument will be logged", action="store_true")
    args = parser.parse_args()

    main(args)