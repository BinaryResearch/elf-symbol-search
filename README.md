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


### 1. `find_symbol_exporters.py`

Search for exporters of a dynamic symbol.

```
$ python3 ./find_symbol_exporters.py 
    --root-path D-Link/DIR-868L/extractions/DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root
    --symbol-name nvram
```

### 2. `find_symbol_importers.py`

Search for importers of a dynamic symbol.

```
$ ./find_symbol_importers.py 
    --root-path D-Link/DIR-868L/extractions/DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root 
    --symbol-name strcpy
```

### 3. `find_dynamic_symbol.py`

Search for exporters and importers of a dynamic symbol.

```
$ ./find_dynamic_symbol.py 
    --root-path D-Link/DIR-868L/extractions/DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root 
    --symbol-name memcpy
```

### 4. `find_any_symbol.py`

Search for presence of any symbol in `.dynsym` or `.symtab` by name.

```
$ ./find_any_symbol.py 
    --root-path D-Link/DIR-868L/extractions/DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root 
    --symbol-name main
    --strict
```

### 5. `find_imports_sources.py`

Identify shared object of origin of every import in the specified binary.

```
$ ./find_imports_sources.py 
    --root-path D-Link/DIR-868L/extractions/DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root 
    --elfbin-path D-Link/DIR-868L/extractions/DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/sbin/httpd
```

### 6. `log_required_libs.py`

Log the set of shared objects required by every dynamically-linked ELF in the given directory tree.

```
$ ./log_required_libs.py 
    --root-path D-Link/DIR-868L/extractions/DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/usr/bin/
```

### 7. `save_all_syms_to_JSON_file.py`

Create a JSON file consisting of records containing symbol info of each ELF file in the traversed directory structure.

```
$ ./save_all_syms_to_JSON_file.py 
    --root-path ~/repos/corpora/CVE/linux-iot-cves/fw/D-Link/DIR-868L/extractions/DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/ 
    --output-path /tmp/dlink-DIR868L-symbols.json
```

**Using `grep` and `wc` to get the number of ELF binaries containing symbols `sprintf`, `system`, and `getenv`:**

```
$ cat /tmp/dlink-DIR868L-symbols.json | grep sprintf | grep system | grep getenv | wc -l

21
```

**Using `grep` and `jq` to list the paths of binaries containing symbols `sprintf`, `system`, and `getenv`:**

```
$ cat /tmp/dlink-DIR868L-symbols.json | grep sprintf | grep system | grep getenv | jq '.file_path'

"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/htdocs/cgibin"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/htdocs/fileaccess.cgi"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/mydlink/signalc"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/sbin/httpd"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/sbin/smbd"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/sbin/nmbd"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/sbin/smbpasswd"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/libavutil.so.51"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/libavutil.so"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/libuClibc-0.9.32.1.so"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/libc.so.0"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/usr/bin/udevinfo"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/usr/bin/udevstart"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/usr/bin/minidlna"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/usr/sbin/wpatalk"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/usr/sbin/fileaccessd"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/usr/sbin/ntpclient"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/usr/sbin/nsbbox"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/usr/sbin/smtpclient"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/usr/sbin/brctl"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/usr/sbin/vconfig"

```


**`jq` query to displaying an example record for binary `brctl`:**

```
$ cat /tmp/dlink-DIR868L-symbols.json | jq 'select(.file_name == "brctl")'

{
  "file_name": "brctl",
  "file_path": "D-Link/DIR-868L/extractions/DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/usr/sbin/brctl",
  "imported_symbols": [
    "_Jv_RegisterClasses",
    "__aeabi_unwind_cpp_pr0",
    "__ctype_b_loc",
    "__deregister_frame_info",
    "__errno_location",
    "__register_frame_info",
    "__uClibc_main",
    "abort",
    "adjtimex",
    "alarm",
    "atoi",
    "bind",
    "close",
    "connect",
    "dup",
    "exit",
    "fcntl",
    "fdopen",
    "fflush",
    "fgetc",
    "fgets",
    "fprintf",
    "fputc",
    "fputs",
    "free",
    "freeaddrinfo",
    "fwrite",
    "gai_strerror",
    "getaddrinfo",
    "getenv",
    "gethostbyname",
    "gethostname",
    "getopt",
    "getopt_long",
    "gettimeofday",
    "herror",
    "htonl",
    "htons",
    "inet_ntoa",
    "inet_ntop",
    "ioctl",
    "listen",
    "localtime",
    "malloc",
    "memcmp",
    "memcpy",
    "memset",
    "ntohl",
    "ntohs",
    "open",
    "openlog",
    "pclose",
    "perror",
    "popen",
    "printf",
    "putchar",
    "puts",
    "qsort",
    "raise",
    "read",
    "recvfrom",
    "select",
    "send",
    "settimeofday",
    "snprintf",
    "socket",
    "sprintf",
    "sscanf",
    "strcasecmp",
    "strcmp",
    "strcpy",
    "strdup",
    "strerror",
    "strftime",
    "strlen",
    "strncpy",
    "strrchr",
    "strtoul",
    "syslog",
    "system",
    "time",
    "ungetc",
    "vfprintf",
    "vprintf",
    "vsnprintf"
  ],
  "exported_symbols": [
    "__bss_end__",
    "__bss_start",
    "__bss_start__",
    "__end__",
    "_bss_end__",
    "_edata",
    "_end",
    "_start",
    "if_freenameindex",
    "if_indextoname",
    "if_nameindex",
    "if_nametoindex",
    "optarg",
    "optind",
    "optopt",
    "stderr",
    "stdin",
    "stdout"
  ],
  "symtab_symbols": []
}
```


**Using `jq` to get the set of unstripped binaries:**

```
$ cat /tmp/dlink-DIR868L-symbols.json | jq 'select(.symtab_symbols | length > 0)' | jq '.file_path'

"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/bin/mDNSResponderPosix"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/sbin/udevtrigger"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/libjpeg.so"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/libstarter.so"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/libgcc_s.so"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/libiconv.so.2.2.0"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/libjpeg.so.8"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/libgdbm.so.3"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/libiconv.so"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/libjpeg.so.8.3.0"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/libiconv.so.2"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/libgcc_s.so.1"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/libpthread.so.0"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/libpthread-0.9.32.1.so"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/modules/nf_nat_pptp.ko"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/modules/nf_conntrack_rtsp.ko"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/modules/nf_conntrack_sip.ko"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/modules/nf_nat_sip.ko"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/modules/nf_conntrack_pptp.ko"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/modules/igs.ko"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/modules/nf_conntrack_ipsec_pass.ko"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/modules/et.ko"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/modules/nf_nat_rtsp.ko"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/modules/emf.ko"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/modules/wl_ap.ko"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/modules/ctf.ko"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/modules/silex/sxuptp.ko"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/modules/silex/jcp_cmd.ko"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/modules/silex/sxuptp_driver.ko"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/modules/silex/jcp.ko"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/modules/silex/sxuptp_devfilter.ko"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/usr/bin/udevinfo"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/usr/bin/udevstart"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/usr/sbin/klogd"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/usr/sbin/mydlinkeventd"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/usr/sbin/email"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/usr/sbin/udevmonitor"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/usr/sbin/portt"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/usr/sbin/tc"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/usr/sbin/trigger"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/usr/sbin/mdtestmail"
"DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/usr/sbin/encimg"
```


**`jq` query to get the set of binaries that import dynamic symbols from more than 5 shared objects:**

```
$ cat /tmp/dlink-DIR868L-symbols.json | jq 'select(.required_libraries | length > 5)' | jq '.file_path'

"D-Link/DIR-868L/extractions/DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/libavformat.so"
"D-Link/DIR-868L/extractions/DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/lib/libavformat.so.53"
"D-Link/DIR-868L/extractions/DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/usr/bin/minidlna"
"D-Link/DIR-868L/extractions/DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/usr/sbin/wps_monitor"
"D-Link/DIR-868L/extractions/DIR868LA1_FW110SHC.bin.extracted/1B0090/squashfs-root/usr/sbin/tr069c"
```