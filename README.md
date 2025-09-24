# elf-symbol-search

## Dependencies

`pyelftools`

## Description

Search file system for dynamic symbols.

Use cases:

 - You've unpacked an archive containing eleventy squijillion ELF binaries and want to know which binaries import/export some symbol (e.g. `strcpy`)
 - You want to know which shared object each import of a particular ELF binary comes from


## Examples


### `find_symbol_exporters.py`

Find all exporters and importers of a dynamic symbol.

```
$ python3 ./find_symbol_exporters.py 
    --root-path D-Link/DIR-868L/extractions/DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root
    --symbol-name nvram
```

### `find_symbol_importers.py`

Find all importers of a dynamic symbol.

```
$ ./find_symbol_importers.py 
    --root-path D-Link/DIR-868L/extractions/DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root 
    --symbol-name strcpy
```

### `find_dynamic_symbol.py`

Find all exporters and importers of a dynamic symbol.

```
$ ./find_dynamic_symbol.py 
    --root-path D-Link/DIR-868L/extractions/DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root 
    --symbol-name strcpy
```


### `find_imports_sources.py`

Identify shared object of origin of every import in binary.

```
$ ./find_imports_sources.py 
    --root-path D-Link/DIR-868L/extractions/DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root 
    --elfbin-path D-Link/DIR-868L/extractions/DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/sbin/httpd
```