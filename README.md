# BaseAddressDiscoverererer

This collection of scripts works together to bruteforce the base load address for a raw binary image based off of string resolution.  It takes as input a file offset parameter - this is the number of bytes into the raw image that are skipped when mapped into memory.  

The two `.java` files in the `ghidra_scripts` directory of this repository must be in one of the ghidra_scripts paths (usually this is `~/ghidra_scripts` - if it doesn't exist, create it an link the two `.java` files into it).

You must also know the Ghidra "LanguageId" and pass it into the `BruteForceAddress.py` script.  For example, this is a Ghida LanguageId for ARM: `ARM:LE:32:v7`

## Example Usage

```shell
python3 BruteForceAddress.py  \
    -p ~/ghidra_11.3.2_PUBLIC \
    -o 8                      \
    firmware.bin              \
    "ARM:LE:32:v7"
```

## System Requirements

Running the `BruteForceAddress.py` script can use several hundred gigabytes of disk space, so make sure you have plenty of empty disk space.  I would also recommend at least 8GB of RAM on whatever host you are running it on.
