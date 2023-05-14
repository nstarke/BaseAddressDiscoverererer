#!/usr/bin/env python3

import argparse, sys, struct

def be(input, results_count=5):
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
    print("address,count")
    for result in s[:results_count]:
        print(f'{hex((int(result[0],base=16)))},{result[1]["count"]}')

def le(input, results_count=5):
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
    print("address,count")
    for result in s[:results_count]:
        print(f'{hex(swap32(int(result[0],base=16)))},{result[1]["count"]}')

def swap32(i):
    return struct.unpack("<I", struct.pack(">I", i))[0]

def main():
    parser = argparse.ArgumentParser(
        prog="BaseAddressDiscoverererer", 
        description="A script that takes raw binary programs and outputs a list of potential base addresses")
    parser.add_argument('filename')
    parser.add_argument('endianness')
    parser.add_argument('results_count', type=int)
    args = parser.parse_args()
    with open(args.filename, 'rb') as input:
        if args.endianness not in ['big', 'little']:
            print('Unsupported Endianness')
            sys.exit(1)
        if args.endianness == 'big':
            be(input, args.results_count)
        elif args.endianness == 'little':
            le(input, args.results_count)

if __name__ == "__main__":        
    main()