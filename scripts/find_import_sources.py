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
                            logging.info(f" [IMPORT]: {sym_name}: {file_handle.name}")
                    else:
                        if symbol_name in sym_name:
                            logging.info(f" [IMPORT]: {sym_name}: {file_handle.name}")


def get_required_shared_objects(elf_file):
    shared_objects_list = []
    #for section in elf_file.iter_sections():
    #    if isinstance(section, SymbolTableSection) and section['sh_type'] == 'SHT_DYNSYM':
    dynamic_section = elf_file.get_section_by_name(".dynamic")
    if not dynamic_section:
        logging.error(f"[!] No '.dynamic' section in '{elf_file.name}'. Quitting.")
        return None

    for tag in dynamic_section.iter_tags():
        if tag.entry.d_tag == "DT_NEEDED":
            shared_objects_list.append(tag.needed)

    return shared_objects_list
    

def parse_file(file_path, root_path):
    with open(file_path, "rb") as f:
        try:
            elf_file = ELFFile(f)
        except ELFError:
            return
        except Exception as e:
            logging.error(f"[!] ERROR: unexpected error parsing '{f.name}'")
            return

        shared_objects_list = get_required_shared_objects(elf_file)

        if shared_objects_list is None or len(shared_objects_list) == 0:
            logging.error(f"[!] No required shared objects found. Quitting.")
            exit(-1)

        print(shared_objects_list)


def main(args):
    root_path = pathlib.Path(args.root_path)
    if not root_path.is_dir():
        logging.error(f"[!] '{args.root_path}' is not a directory. Quitting.")
        exit(-1)

    elfbin_path = pathlib.Path(args.elfbin_path)
    if not elfbin_path.is_file():
        logging.error(f"[!] '{args.elfbin_path}' is not a file. Quitting.")
        exit(-1)

    parse_file(elfbin_path, root_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root-path", help="Root directory of file system search", required=True)
    parser.add_argument("--elfbin-path", help="Path of ELF binary containing imports to analyze", required=True)
    args = parser.parse_args()

    main(args)