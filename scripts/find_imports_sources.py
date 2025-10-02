#!/usr/bin/env python3

import pathlib
import argparse
import logging
from enum import Enum
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.common.exceptions import ELFError


class DynSymType(Enum):
    IMPORT = 0
    EXPORT = 1


LOGFILE = "/tmp/elf-symbol-search.log"
logging.basicConfig(filename=LOGFILE,
                    level=logging.INFO)


# If dynamic symbol["st_shndx"] == "SH_UNDEF", it is an imported symbol.
# Else, it is an export.
#
def get_dynamic_symbols_by_type(elf_file, dynsym_type):
    symbols_list = []
    for section in elf_file.iter_sections():
        if isinstance(section, SymbolTableSection) and section['sh_type'] == 'SHT_DYNSYM':
            for symbol in section.iter_symbols():
                sym_name = symbol.name

                if sym_name is None or len(sym_name) == 0:
                    continue

                shndx = symbol["st_shndx"]
                
                if dynsym_type == DynSymType.IMPORT:
                     if shndx == "SHN_UNDEF":
                        symbols_list.append(sym_name)

                if dynsym_type == DynSymType.EXPORT:
                    if shndx == "SHN_UNDEF":
                        continue
                    else:
                        symbols_list.append(sym_name)

    return symbols_list


def get_required_shared_objects(elf_file):
    shared_objects_list = []
    #for section in elf_file.iter_sections():
    #    if isinstance(section, SymbolTableSection) and section['sh_type'] == 'SHT_DYNSYM':
    dynamic_section = elf_file.get_section_by_name(".dynamic")
    if not dynamic_section:
        logging.error("[!] No '.dynamic' section found. Quitting.")
        return None

    for tag in dynamic_section.iter_tags():
        if tag.entry.d_tag == "DT_NEEDED":
            shared_objects_list.append(tag.needed)

    return shared_objects_list


def find_file(root_path, file_name):
    for path in pathlib.Path(root_path).rglob("*"):
        if not pathlib.Path.is_file(path):
            continue

        if path.name == file_name:
            return path
        
    return None


def parse_file(file_path, root_path):
    with open(file_path, "rb") as f:
        try:
            elf_file = ELFFile(f)
        except ELFError:
            return
        except Exception as e:
            logging.error(f"[!] ERROR: unexpected error parsing '{f.name}'")
            return

        logging.info(f" Getting required shared objects of '{file_path}'")

        # 1. Get names of required shared objects
        shared_objects_list = get_required_shared_objects(elf_file)
        if shared_objects_list is None or len(shared_objects_list) == 0:
            logging.error(f"[!] No required shared objects found. Quitting.")
            exit(-1)

        logging.info(f" REQUIRED SHARED OBJECTS:\t{shared_objects_list}")
        print(f" REQUIRED SHARED OBJECTS:\t\t{shared_objects_list}")
        
        # 2. Get list of imports of ELF file
        dynamic_imports_list = get_dynamic_symbols_by_type(elf_file, DynSymType.IMPORT)
        if len(dynamic_imports_list) == 0:
            logging.error(f"[!] No dynamic imports found. Quitting.")
            exit(-1)

        #logging.info(f" Dynamic imports: {dynamic_imports_list}")

        # 3. Create dictionary of { "exported symbol": [list of shared objects exporting symbol] } pairs
        exports_dict = {}
        for shared_object_name in shared_objects_list:
            so_path = find_file(root_path, shared_object_name)
            if so_path is None:
                logging.info(f"[!] Shared object '{so_path}' not found.")
                continue

            dynamic_exports_list = []
            with open(so_path, "rb") as so_f:
                try:
                    so_elf_file = ELFFile(so_f)
                except ELFError as e:
                    logging.error(f"[!]'Caught ELFError when parsing {f.name}': {e}")
                    continue
                except Exception as e:
                    logging.error(f"[!] Unexpected error parsing '{f.name}': {e}")
                    continue

                dynamic_exports_list = get_dynamic_symbols_by_type(so_elf_file, DynSymType.EXPORT)
                if dynamic_exports_list is None or len(dynamic_exports_list) == 0:
                    logging.error(f"[!] No dynamic exports found in '{so_path}'")
                    continue

            #print(len(dynamic_exports_list))
            for dynsym_name in dynamic_exports_list:
                if dynsym_name not in exports_dict:
                    exports_dict[dynsym_name] = [shared_object_name]
                else:
                    exports_dict[dynsym_name].append(shared_object_name)

        # 4. Perform lookup of each ELF file import symbol in exports dictionary
        import_source_map = {}
        for imported_symbol in sorted(dynamic_imports_list):
            if imported_symbol in exports_dict.keys():
                #logging.info(f" {imported_symbol:30}\t{exports_dict[imported_symbol]}")
                import_source_map[imported_symbol] = exports_dict[imported_symbol]
                print(f" {imported_symbol:30}\t{exports_dict[imported_symbol]}")

        logging.info(f" IMPORT TO SOURCE MAPPING:\t{import_source_map}")

def main(args):
    print(f"********************** Output written to '{LOGFILE}' **********************")

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
