#!/usr/bin/env python3

import argparse, subprocess, math, pathlib, shutil, os
import xml.etree.ElementTree as ET

def analyze_xml_result(name, offset):
    with open("workspace/" + name + "/results/" + offset + "/result.xml", "r+") as f:
        xml = "<ghidra_results>" + f.read() + "</ghidra_results>"
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
        address_out = int(address_out.text)

        offset_out = max_node.find(".//offset")
        offset_out = int(offset_out.text)

        print("Total Strings: " + str(total_out))
        print("Referenced Strings: " + str(referenced_out))
        print("Base Address: " + str(address_out))
        print("Offset: " + str(offset_out))

def run_ghidra_analyze(ghidra_path, filename):
    cmd = ghidra_path + '/support/analyzeHeadless workspace/' + filename + "/ghidra " + filename + " -deleteProject -process -recursive -preScript SetProgramAttributes.java -postScript CountReferencedStrings.java"
    subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)

def run_ghidra_import(ghidra_path, filename, languageId):
    cmd = ghidra_path + '/support/analyzeHeadless workspace/' + filename + '/ghidra ' + filename + ' -import workspace/' + filename + '/out/* -recursive -noanalysis -processor "' + languageId + '" -loader BinaryLoader'    
    subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
    
def bruteforce(ghidra_path, startIdx, end, filename, languageId, interval, offset):
    p = pathlib.Path(filename)
    o = hex(offset).replace("0x", "")
    
    print("Building Address/Offset Filesystem Structure")
    for i in range(math.ceil((((end) - (startIdx)) / interval))):
        address = hex(startIdx + (i * interval)).replace('0x', '')
        ws = "workspace/" + p.name + "/out/" + o + "/" + address
        os.makedirs(ws, exist_ok=True)
        os.symlink(filename, ws + "/" + p.name)

    os.makedirs("workspace/" + p.name + "/ghidra", exist_ok=True)
    os.makedirs("workspace/" + p.name + "/results/" + o, exist_ok=True)

    print("Running Ghidra Import")
    run_ghidra_import(ghidra_path, p.name, languageId)
    
    print("Running Ghidra Analysis")
    run_ghidra_analyze(ghidra_path, p.name)
    
    print("Analyzing Results")
    analyze_xml_result(p.name, o)
    

def main():
    parser = argparse.ArgumentParser(
        prog="BruteForceDiscover", 
        description="A script that takes raw binary programs and bruteforces their load offset")
    parser.add_argument('filename')
    parser.add_argument('languageId')
    parser.add_argument('-s', '--start', type=lambda x: int(x, 16), default=0, const=0, nargs='?')
    parser.add_argument('-e', '--end', type=lambda x: int(x, 16), default=0xffffffff, const=0xffffffff, nargs='?')
    parser.add_argument('-i', '--interval', type=lambda x: int(x, 16), default=0x10000, const=0x10000, nargs='?')
    parser.add_argument('-o', '--offset', type=lambda x: int(x, 16), default=0, const=0, nargs='?')
    parser.add_argument('-p', '--ghidra-path', type=str)

    args = parser.parse_args()
    bruteforce(args.ghidra_path, args.start, args.end, args.filename, args.languageId, args.interval, args.offset)

if __name__ == "__main__":        
    main()