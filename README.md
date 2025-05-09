# BaseAddressDiscoverererer

This tool will help gather the necessary information to reverse engineer a raw binary program. The input to this tool should be a binary program that does not have a header (ELF, PE, Mach-O, etc). Given this input, the tool will determine the instruction set architecture, output the offset into the input file that the program begins on, and the base address that the program is loaded into memory at. With these three pieces of information, you can load the binary file into your Reverse Engineering tool suite of choice (Ghidra, IDA Pro, Binary Ninja, etc) and effectively reverse engineer it.

## Quick Start

If you have a binary file and you want to quickly get started, there is a helper script called `run.sh` that will install all necessary components, configure the envinronment, and run the tool for you. You can run it like this:

For Ubuntu/Debian:

```bash
bash run.sh $INPUT_RAW_BINARY_FILE_PATH
```

Or for Windows 10/11:

```batch
run.bat %INPUT_RAW_BINARY_FILE_PATH%
```
## Performance Note

By default, the tool performs a brute force search of the most significant 16 bits of the 32-bit address space. Even on beefy machines, this can take days.  **This tool is best run on a server**

## Supported Operating Systems

* Ubuntu (Tested against 24.04)
* Windows (Tested against 11)

## Running the Python Script directly

For more fine grain control, you can run the Python script directly. The script is called `BruteForceAddress.py`.

```bash
python BruteForceAddress.py -h
usage: BruteForceAddress [-h] [-s [START]] [-e [END]] [-i [INTERVAL]] [-o [OFFSET]] [-g GHIDRA_PATH] [-w [WORKSPACE]] [-l LANGUAGEID] [-f [FORMAT]] [--skip]
                         filename

A script that takes raw binary programs and bruteforces their load offset

positional arguments:
  filename              The input file to bruteforce

options:
  -h, --help            show this help message and exit
  -s, --start [START]
  -e, --end [END]
  -i, --interval [INTERVAL]
  -o, --offset [OFFSET]
  -g, --ghidra-path GHIDRA_PATH
  -w, --workspace [WORKSPACE]
  -l, --languageId LANGUAGEID
  -f, --format [FORMAT]
  --skip                Skip Bruteforce and only perform analysis
```

`--start` is the starting address to bruteforce from. The default is `0x00000000`.

`--end` is the ending address to bruteforce to. The default is `0xFFFF0000`.

`--interval` is the interval to bruteforce by. The default is `0x10000`.

`--offset` is the offset into the file that the program begins at. The default is `0`. This is used to determine the base address of the program.

`--ghidra-path` is the path to the Ghidra installation. This is used to run Ghidra in headless mode.

`--workspace` is the workspace to use for the tool.  This can grow to several hundred gigabytes in size.

`--languageId` is the language ID to use in Ghidra. An example is `x86:LE:64:default`. This is specific to Ghidra.

`--format` is the format of the input file. Can be `txt`, `csv`, `json`, `cli`, or `xml`. 

`--skip` will skip the bruteforce and only perform analysis. This will only work if analysis has previously been performed.

## Components

This tool uses the following components:
- Ghidra: https://ghidra-sre.org/
- CPU_REC: https://github.com/airbus-seclab/cpu_rec