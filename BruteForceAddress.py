#!/usr/bin/env python3

import argparse, subprocess, math, pathlib, shutil, os, sys
import xml.etree.ElementTree as ET
from cpu_rec.cpu_rec import which_arch

def analyze_xml_result(name, offset, workspace, skip = False):
    with open(workspace + "/" + name + "/results/" + offset + "/result.xml", "r+") as f:
        if skip:
            xml = f.read()
        else:
            xml = "<ghidra_results>" + f.read() + "</ghidra_results>"
            f.truncate(0)
            f.write(xml)
        root = ET.fromstring(xml)
        maximum = -1
        max_node = None
        for child in root.findall(".//ghidra_result"):
            total = child.find(".//total")
            total = int(total.text)
            if total > maximum:
                maximum = total
                max_node = child

        total_out = max_node.find(".//total")
        total_out = int(total_out.text)

        referenced_out = max_node.find(".//referenced")
        referenced_out = int(referenced_out.text)
        
        address_out = max_node.find(".//address")
        address_out = int(address_out.text, 16)

        offset_out = max_node.find(".//offset")
        offset_out = int(offset_out.text, 16)

        print("Total Strings: " + str(total_out))
        print("Referenced Strings: " + str(referenced_out))
        print("Base Address: " + hex(address_out))
        print("Offset: " + hex(offset_out))

def run_ghidra_analyze(ghidra_path, filename, offset, workspace):
    cmd = ghidra_path + '/support/analyzeHeadless ' + workspace + '/' + filename + "/ghidra/" + str(offset) + ' ' + filename + " -deleteProject -process -recursive -preScript SetProgramAttributes.java -postScript CountReferencedStrings.java"
    subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)

def run_ghidra_import(ghidra_path, filename, languageId, offset, workspace):
    cmd = ghidra_path + '/support/analyzeHeadless ' + workspace + '/' + filename + '/ghidra/' + str(offset) + ' ' + filename + ' -import ' + workspace + '/' + filename + '/out/* -recursive -noanalysis -processor "' + languageId + '" -loader BinaryLoader -loader-fileOffset ' + offset
    subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
    
def bruteforce(ghidra_path, startIdx, end, filename, languageId, interval, offset, workspace):
    p = pathlib.Path(filename)
    o = hex(offset).replace("0x", "")
    
    if os.path.isdir(workspace):
        shutil.rmtree(workspace)
    
    print("Building Address/Offset Filesystem Structure")
    for i in range(math.ceil((((end) - (startIdx)) / interval))):
        address = hex(startIdx + (i * interval)).replace('0x', '')
        ws = workspace + "/" + p.name + "/out/" + o + "/" + address
        os.makedirs(ws, exist_ok=True)
        os.symlink(filename, ws + "/" + p.name)

    os.makedirs(workspace + "/" + p.name + "/ghidra/" + o, exist_ok=True)
    os.makedirs(workspace + "/" + p.name + "/results/" + o, exist_ok=True)

    print("Running Ghidra Import")
    run_ghidra_import(ghidra_path, p.name, languageId, o, workspace)
    
    print("Running Ghidra Analysis")
    run_ghidra_analyze(ghidra_path, p.name, o, workspace)
    
    print("Analyzing Results")
    analyze_xml_result(p.name, o, workspace)

    shutil.rmtree(workspace + "/" + p.name + "/out/" + o)
    
def bruteforce_offset(ghidra_path, filename, languageId, workspace):
    p = pathlib.Path(filename)
    os.makedirs(workspace + '/' + p.name + "/ghidra/offset", exist_ok=True)
    cmd = ghidra_path + '/support/analyzeHeadless ' + workspace + '/' + p.name + "/ghidra/offset " + p.name + " -import " + filename + " -noanalysis -preScript BruteForceFileOffset.java -processor " + languageId + " -loader BinaryLoader"
    output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
    fileOffset = output[output.find("<fileOffset>") + len("<fileOffset>"):output.find("</fileOffset>")]
    if fileOffset == -1:
        raise Exception("Error: Could not find file offset in Ghidra output")
    else:
        print("File Offset Found: " + fileOffset)
    return int(fileOffset)

def detect_architecture(filename):
    with open(filename, 'rb') as f:
        data = f.read()
        arch = which_arch(data)
    return convert_cpu_rec_to_ghidra(arch)

def convert_cpu_rec_to_ghidra(arch):
    if 'ARM' in arch:
        if 'el' in arch or 'hf' in arch:
            return "ARM:LE:32:v8"
        elif 'eb' in arch:
            return "ARM:BE:32:v8"
    if 'AARCH64' in arch:
        raise Exception("AARCH64 not supported")
    if 'PPC' in arch:
        if 'el' in arch:
            return "PPC:LE:32:default"
        elif 'eb' in arch:
            return "PPC:BE:32:default"
    if 'MIPS' in arch:
        if 'el' in arch:
            return "MIPS:LE:32:default"
        elif 'eb' in arch:
            return "MIPS:BE:32:default"
    if 'X86-64' in arch:
        return "x86:LE:64:default"
    if 'X86' in arch:
        return "x86:LE:32:default"
    raise Exception("Error: Could not auto detect architecture - you must manually set the languageId")
    
def main():
    parser = argparse.ArgumentParser(
        prog="BruteForceDiscover", 
        description="A script that takes raw binary programs and bruteforces their load offset")
    parser.add_argument('filename')
    parser.add_argument('-s', '--start', type=lambda x: int(x, 16), default=0, const=0, nargs='?')
    parser.add_argument('-e', '--end', type=lambda x: int(x, 16), default=0xffffffff, const=0xffffffff, nargs='?')
    parser.add_argument('-i', '--interval', type=lambda x: int(x, 16), default=0x10000, const=0x10000, nargs='?')
    parser.add_argument('-o', '--offset', type=lambda x: int(x, 16), default=0, const=0, nargs='?')
    parser.add_argument('-g', '--ghidra-path', type=str)
    parser.add_argument('-w', '--workspace', type=str, default="workspace", const="workspace", nargs='?')
    parser.add_argument('-l', '--languageId', type=str)
    parser.add_argument('--skip', action='store_true', help="Skip Bruteforce and only perform analysis")

    args = parser.parse_args()
    p = pathlib.Path(args.filename)
    print("Results for: " + p.name)
    if args.skip:
        o = hex(args.offset).replace("0x", "")
        print("Skipping import and analyzing existing results")
        analyze_xml_result(p.name, o, args.workspace, True)
    else:
        if not args.languageId:
            arch = detect_architecture(args.filename)
            print("LanguageId auto detected: " + arch)
        else:
            arch = args.languageId
        if args.offset == 0:
            fileOffset = bruteforce_offset(args.ghidra_path, args.filename, arch, args.workspace)
        bruteforce(args.ghidra_path, args.start, args.end, args.filename, arch, args.interval, fileOffset, args.workspace)

if __name__ == "__main__":        
    main()