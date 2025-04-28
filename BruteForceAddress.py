#!/usr/bin/env python3

import argparse, subprocess, math, pathlib, shutil, multiprocessing
import xml.etree.ElementTree as ET

def analyze_xml_result():
    with open("/tmp/result.xml", "r+") as f:
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

        print(ET.tostring(max_node, encoding='unicode')

def run_ghidra_analyze(ghidra_path, filename):
    cpus = multiprocessing.cpu_count() - 4
    cmd = ghidra_path + '/support/analyzeHeadless /tmp ' + filename + " -process -recursive -postScript CountReferencedStrings.java"
    subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)

def run_ghidra_import(ghidra_path, filename, languageId, address, offset):
    address = hex(address).replace('0x', '')
    offset = hex(offset).replace('0x', '')
    cmd = ghidra_path + '/support/analyzeHeadless /tmp ' + filename + '/' + offset + '/' + address  + ' -import /tmp/' + filename + ' -noanalysis -processor "' + languageId + '" -loader BinaryLoader -loader-baseAddr ' + address + ' -loader-fileOffset ' + offset
    subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
    
def bruteforce(ghidra_path, startIdx, end, filename, languageId, interval, offset):
    p = pathlib.Path(filename)
    shutil.copy(filename, "/tmp/" + p.name)
    for i in range(math.ceil((((end) - (startIdx)) / interval))):
        print("Importing Address: " + hex(startIdx + (i * interval)))
        run_ghidra_import(ghidra_path, p.name, languageId, (startIdx + (i * interval)), offset)
    
    run_ghidra_analyze(ghidra_path, p.name)
    
    analyze_xml_result()
    

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