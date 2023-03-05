#!/usr/bin/env python3

import argparse, sys

def be(input):
    dw = input.read(4)
    candidates = set([])
    while dw:
        if dw != b"\x00\x00\x00\x00" and dw[2:] == b"\x00\x00":
            candidates.add(dw)
        dw = input.read(4)
    input.seek(0)
    results = dict([])
    dw = input.read(4)
    while dw:
        check = dw[0:2] + b"\x00\x00"
        if check not in candidates:
            dw = input.read(4)
            continue

        if check.hex() in results.keys():
            results[check.hex()]['count'] = results[check.hex()]['count'] + 1
        else:
            results[check.hex()] = {'count': 1 }
        dw = input.read(4)
    
    s = sorted(results.items(), key=lambda d: d[1]['count'], reverse=True)
    print("Top 5 results")
    for result in s[:5]:
        print(result)

def le(input):
    dw = input.read(4)
    candidates = set([])
    while dw:
        if dw != b"\x00\x00\x00\x00" and dw[0:2] == b"\x00\x00":
            candidates.add(dw)
        dw = input.read(4)
    input.seek(0)
    results = dict([])
    dw = input.read(4)
    while dw:
        check = b"\x00\x00" + dw[2:] 
        if check not in candidates:
            dw = input.read(4)
            continue

        if check.hex() in results.keys():
            results[check.hex()]['count'] = results[check.hex()]['count'] + 1
        else:
            results[check.hex()] = {'count': 1 }
        dw = input.read(4)
    
    s = sorted(results.items(), key=lambda d: d[1]['count'], reverse=True)
    print("Top 5 results")
    for result in s[:5]:
        print(result)

def main():
    parser = argparse.ArgumentParser(
        prog="BaseAddressDiscoverererer", 
        description="A script that takes raw binary programs and outputs a list of potential base addresses")
    parser.add_argument('filename')
    parser.add_argument('endianness')
    args = parser.parse_args()
    with open(args.filename, 'rb') as input:
        if args.endianness not in ['big', 'little']:
            print('Unsupported Endianness')
            sys.exit(1)
        if args.endianness == 'big':
            be(input)
        elif args.endianness == 'little':
            le(input)

if __name__ == "__main__":        
    main()