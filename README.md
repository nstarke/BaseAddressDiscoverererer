# BaseAddressDiscoverererer

This is a set of python3 scripts for bruteforcing the load address of a raw binary program.  The scripts use ghidra to analyze raw binary data using a series of load addresses and then checking how many internal strings were resolved in the analysis for each base address attempt.  

This is a useful toolset when you have a raw binary image with no ELF, PE32, Mach-O, or COFF header, as we sometimes see in low-level boot images for embedded devices (think `U-boot`, etc).
## Requirements

These scripts require Ghidra `11.0.3` to be installed at `/opt/ghidra-11.0.3` and the `CountReferencedStrings.java` to be in one of the ghidra script locations, preferably `~/ghidra_scripts`.  If `CountReferencedStrings.java` is left in the root directory, the scripts will fail to work properly; I recommend you `mv` the `CountReferencedStrings.java` file to a ghidra script directory.  Make sure it is not in the repository directory you are running the scripts from.
