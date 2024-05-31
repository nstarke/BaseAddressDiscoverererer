#!/usr/bin/env python3

import argparse, pathlib, random, operator, json, multiprocessing, threading, datetime, math

def main():
    parser = argparse.ArgumentParser(
        prog="BruteForceOffset",
        description="Divide firmware into n sized chunks to use with BruteForceAddress.py"
    )

    parser.add_argument('filename')
    parser.add_argument('-i', '--interval', type=lambda x: int(x, 16), default=0x10, const=0x10, nargs='?')
    parser.add_argument('-c', '--count' , type=lambda x: int(x, 16), default=0x20, const=0x20, nargs='?')
    args = parser.parse_args() 
    p = pathlib.Path(args.filename)
    with open(p, 'rb') as f:
        data = f.read()

        for i in range(args.count):
            offset = i * args.interval
            with open('binaries/' + p.name + "_" + offset + ".headerless.bin", 'wb') as w:
                w.write(data[offset:])

if __name__ == "__main__":        
    main()