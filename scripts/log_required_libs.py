#!/usr/bin/env python3

import pathlib
import argparse
import logging
from enum import Enum
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError


class DynSymType(Enum):
    IMPORT = 0
    EXPORT = 1


LOGFILE = "/tmp/elf-symbol-search.log"
logging.basicConfig(filename=LOGFILE,
                    level=logging.INFO)


def get_required_shared_objects(elf_file):
    shared_objects_list = []
    dynamic_section = elf_file.get_section_by_name(".dynamic")
    if not dynamic_section:
        return None

    for tag in dynamic_section.iter_tags():
        if tag.entry.d_tag == "DT_NEEDED":
            shared_objects_list.append(tag.needed)

    return shared_objects_list


def parse_file(file_path):
    with open(file_path, "rb") as f:
        try:
            elf_file = ELFFile(f)
        except ELFError:
            return
        except Exception as e:
            logging.error(f"[!] ERROR: unexpected error parsing '{f.name}'")
            return

        # Get names of required shared objects
        shared_objects_list = get_required_shared_objects(elf_file)
        if shared_objects_list is None or len(shared_objects_list) == 0:
            return

        logging.info(f" {f.name} DT_NEEDED: {shared_objects_list}")
        #print(f" {f.name} DT_NEEDED: {shared_objects_list}")
        

def main(args):
    print(f"\n********************** Output written to '{LOGFILE}' **********************\n")

    root_path = pathlib.Path(args.root_path)
    if not root_path.is_dir():
        logging.error(f"[!] '{args.root_path}' is not a directory. Quitting.")
        exit(-1)

    for file_path in pathlib.Path(root_path).rglob("*"):
        if not pathlib.Path.is_file(file_path):
            continue 
        else:
            parse_file(file_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root-path", help="Root directory of file system search", required=True)
    args = parser.parse_args()

    main(args)