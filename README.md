# elf-symbol-search

## Dependencies

`pyelftools`

## Description

Search file system for symbols contained in ELF files.

Use cases:

 - You've unpacked a firmware blob containing a large number of ELF binaries and want to know which binaries import/export some symbol (e.g. `strcpy`)
 - You want to know which shared object each import of a particular ELF binary comes from
 - You want to know the set of shared objects required by each dynamically-linked ELF because you want to investigate library dependencies

Note: all search results are output to `/tmp/elf-symbol-search.log`.

## Examples


### `find_symbol_exporters.py`

Search for exporters of a dynamic symbol.

```
$ python3 ./find_symbol_exporters.py 
    --root-path D-Link/DIR-868L/extractions/DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root
    --symbol-name nvram
```

### `find_symbol_importers.py`

Search for importers of a dynamic symbol.

```
$ ./find_symbol_importers.py 
    --root-path D-Link/DIR-868L/extractions/DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root 
    --symbol-name strcpy
```

### `find_dynamic_symbol.py`

Search for exporters and importers of a dynamic symbol.

```
$ ./find_dynamic_symbol.py 
    --root-path D-Link/DIR-868L/extractions/DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root 
    --symbol-name memcpy
```

### `find_any_symbol.py`

Search for presence of any symbol in `.dynsym` or `.symtab` by name.

```
$ ./find_any_symbol.py 
    --root-path D-Link/DIR-868L/extractions/DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root 
    --symbol-name main
    --strict
```

### `find_imports_sources.py`

Identify shared object of origin of every import in the specified binary.

```
$ ./find_imports_sources.py 
    --root-path D-Link/DIR-868L/extractions/DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root 
    --elfbin-path D-Link/DIR-868L/extractions/DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/sbin/httpd
```

### `log_required_libs.py`

Log the set of shared objects required by every dynamically-linked ELF in the given directory tree.

```
$ ./log_required_libs.py 
    --root-path D-Link/DIR-868L/extractions/DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/usr/bin/
```