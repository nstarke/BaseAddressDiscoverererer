#!/usr/bin/env python3

import argparse, subprocess, math, pathlib, shutil, os, sys, json
import xml.etree.ElementTree as ET
from cpu_rec.cpu_rec import which_arch

def analyze_xml_result(name, offset, workspace, skip = False):
    with open(workspace + os.sep + name + os.sep + "results" + os.sep + offset + os.sep + "result.xml", "r+") as f:
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

        return (total_out, referenced_out, address_out, offset_out)
        
def save_results(name, total_out, referenced_out, address_out, offset_out, workspace, languagedId, format):
    referenced_str = hex(referenced_out).replace("0x", "")
    total_str = hex(total_out).replace("0x", "")
    offset_str = hex(offset_out).replace("0x", "")  
    address_str = hex(address_out).replace("0x", "")
    
    if format == "cli":
        print("Results for: " + name)
        print("LanguageId: " + languagedId)
        print("Total Strings (hex): " + total_str)
        print("Referenced Strings (hex): " + referenced_str)
        print("Base Address (hex): " + address_str)
        print("Offset (hex): " + offset_str)
    elif format == "json":
        p = workspace + os.sep + name + os.sep + "results" + os.sep + offset_str + os.sep + "results.json"
        result = {
            "name": name,
            "languageId": languagedId,
            "total": total_out,
            "referenced": referenced_out,
            "address": address_out,
            "offset": offset_out
        }
        with open(p, "w+") as f:
            json.dump(result, f, indent=4)
        print("Results saved to: " + p)
    elif format == "csv":
        p = workspace + os.sep + name + os.sep + "results" + os.sep + offset_str + os.sep + "results.csv"
        with open(p, "w+") as f:
            f.write("Name,LanguageId,Total,Referenced,Address,Offset\n")
            f.write('"' + name + '","' + languagedId + '",' + str(total_out) + "," + str(referenced_out) + "," + address_str + "," + offset_str + "\n")
        print("Results saved to: " + p)
    elif format == "xml":
        p = workspace + os.sep + name + os.sep + "results" + os.sep + offset_str + os.sep + "results.xml"
        root = ET.Element("ghidra_results")
        result = ET.SubElement(root, "ghidra_result")
        name_element = ET.SubElement(result, "name")
        name_element.text = name
        languagedId_element = ET.SubElement(result, "languageId")
        languagedId_element.text = languagedId
        total_element = ET.SubElement(result, "total")
        total_element.text = str(total_out)
        referenced_element = ET.SubElement(result, "referenced")
        referenced_element.text = str(referenced_out)
        address_element = ET.SubElement(result, "address")
        address_element.text = hex(address_out)
        offset_element = ET.SubElement(result, "offset")
        offset_element.text = hex(offset_out)
        
        tree = ET.ElementTree(root)
        tree.write(p, encoding='utf-8', xml_declaration=True)  
        print("Results saved to: " + p)  
    elif format == "txt":
        p = workspace + os.sep + name + os.sep + "results" + os.sep + offset_str + os.sep + "results.txt"
        with open(p, "w+") as f:
            f.write("Name: " + name + "\n")
            f.write("LanguageId: " + languagedId + "\n")
            f.write("Total Strings: " + str(total_out) + "\n")
            f.write("Referenced Strings: " + str(referenced_out) + "\n")
            f.write("Base Address: " + hex(address_out) + "\n")
            f.write("Offset: " + hex(offset_out) + "\n")
        print("Results saved to: " + p)

def run_ghidra_analyze(ghidra_path, filename, offset, workspace):
    env = os.environ.copy()
    env["BAD_WORKSPACE"] = workspace
    cmd = ghidra_path + os.sep + 'support' + os.sep + 'analyzeHeadless ' + workspace + os.sep + filename + os.sep + "ghidra" + os.sep + str(offset) + ' ' + filename + " -deleteProject -process -recursive -preScript SetProgramAttributes.java -postScript CountReferencedStrings.java -max-cpu " + str(os.cpu_count())
    subprocess.check_output(cmd, env=env, shell=True, text=True, stderr=subprocess.DEVNULL)

def run_ghidra_import(ghidra_path, filename, languageId, offset, workspace):
    cmd = ghidra_path + os.sep + 'support' + os.sep + 'analyzeHeadless ' + workspace + os.sep + filename + os.sep + 'ghidra' + os.sep + str(offset) + ' ' + filename + ' -import ' + workspace + os.sep + filename + os.sep + 'out -recursive -noanalysis -processor "' + languageId + '" -loader BinaryLoader -loader-fileOffset ' + offset + ' -max-cpu ' + str(os.cpu_count())
    subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
    
def bruteforce(ghidra_path, startIdx, end, filename, languageId, interval, offset, workspace, format):
    p = pathlib.Path(filename)
    o = hex(offset).replace("0x", "")
    
    if os.path.isdir(workspace):
        shutil.rmtree(workspace)
    
    print("Building Address/Offset Filesystem Structure")
    for i in range(math.ceil((((end) - (startIdx)) / interval))):
        address = hex(startIdx + (i * interval)).replace('0x', '')
        ws = workspace + os.sep + p.name + os.sep + "out" + os.sep + o + os.sep + address
        os.makedirs(ws, exist_ok=True)
        os.symlink(filename, ws + os.sep + p.name)

    os.makedirs(workspace + os.sep + p.name + os.sep + "ghidra" + os.sep + o, exist_ok=True)
    os.makedirs(workspace + os.sep + p.name + os.sep + "results" + os.sep + o, exist_ok=True)

    print("Running Ghidra Import")
    run_ghidra_import(ghidra_path, p.name, languageId, o, workspace)
    
    print("Running Ghidra Analysis")
    run_ghidra_analyze(ghidra_path, p.name, o, workspace)
    
    print("Analyzing Results")
    result = analyze_xml_result(p.name, o, workspace)
    
    print("Saving Results")
    save_results(p.name, result[0], result[1], result[2], result[3], workspace, languageId, format)
    shutil.rmtree(workspace + os.sep + p.name + os.sep + "out" + os.sep + o)
    
def bruteforce_offset(ghidra_path, filename, languageId, workspace):
    p = pathlib.Path(filename)
    os.makedirs(workspace + os.sep + p.name + os.sep + "ghidra" + os.sep + "offset", exist_ok=True)
    cmd = ghidra_path + os.sep + 'support' + os.sep + 'analyzeHeadless ' + workspace + os.sep + p.name + os.sep + "ghidra" + os.sep + "offset " + p.name + " -import " + filename + " -noanalysis -preScript BruteForceFileOffset.java -processor " + languageId + " -loader BinaryLoader"
    output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
    fileOffset = output[output.find("<fileOffset>") + len("<fileOffset>"):output.find("</fileOffset>")]
    if fileOffset == str(-1):
        print("Error: Could not find file offset in Ghidra output")
        sys.exit(1)
    else:
        print("File Offset Found: " + fileOffset)
    return int(fileOffset)

def detect_architecture(filename):
    with open(filename, 'rb') as f:
        data = f.read()
        arch = which_arch(data)
        if not arch:
            print("Error: Could not detect architecture")
            sys.exit(1)
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
    
    print("Error: Unsupported architecture: " + arch)
    sys.exit(1)
    
def main():
    parser = argparse.ArgumentParser(
        prog="BruteForceAddress", 
        description="A script that takes raw binary programs and bruteforces their load offset")
    parser.add_argument('filename', type=str, help="The input file to bruteforce")
    parser.add_argument('-s', '--start', type=lambda x: int(x, 16), default=0, const=0, nargs='?')
    parser.add_argument('-e', '--end', type=lambda x: int(x, 16), default=0xffffffff, const=0xffffffff, nargs='?')
    parser.add_argument('-i', '--interval', type=lambda x: int(x, 16), default=0x10000, const=0x10000, nargs='?')
    parser.add_argument('-o', '--offset', type=lambda x: int(x, 16), default=0, const=0, nargs='?')
    parser.add_argument('-g', '--ghidra-path', type=str)
    parser.add_argument('-w', '--workspace', type=str, default="workspace", const="workspace", nargs='?')
    parser.add_argument('-l', '--languageId', type=str)
    parser.add_argument('-f', '--format', type=str, default="txt", const="txt", nargs='?')
    parser.add_argument('--skip', action='store_true', help="Skip Bruteforce and only perform analysis")

    args = parser.parse_args()
    
    ghidra_home = os.getenv("GHIDRA_HOME")
    
    if not args.ghidra_path and not ghidra_home:
        print("Error: Ghidra path not specified and GHIDRA_HOME environment variable not set")
        sys.exit(1)
        
    if not ghidra_home:
        ghidra_home = args.ghidra_path
    
    if not os.path.isdir(ghidra_home) or not os.path.isfile(ghidra_home + os.sep + "support" + os.sep + "analyzeHeadless"):
        print("Error: Ghidra path does not exist or is not installed correctly")
        sys.exit(1)
        
    if not args.format in ["cli", "json", "csv", "xml", "txt"]:
        print("Error: Invalid format specified. Must be one of: cli, json, csv, xml, txt")
        sys.exit(1)
    
    p = pathlib.Path(args.filename)
    if not p.is_file():
        print("Error: File does not exist")
        sys.exit(1)
    
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
            fileOffset = bruteforce_offset(ghidra_home, args.filename, arch, args.workspace)
        else:
            fileOffset = args.offset
        bruteforce(ghidra_home, args.start, args.end, args.filename, arch, args.interval, fileOffset, args.workspace, args.format)

if __name__ == "__main__":        
    main()