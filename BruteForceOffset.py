#!/usr/bin/env python3

import argparse, subprocess, random, operator, json, multiprocessing, threading, datetime, math

def main():
    parser = argparse.ArgumentParser(
        prog="BruteForceOffset",
        help="Divide firmware into n sized chunks to use with BruteForceAddress.py"
    )

    parser.add_argument('filename')
    parser.add_argument('interval')
    parser.add_argument('count')
    args = parser.parse_args() 
    with open(args.filename, 'rb') as f:
        data = f.read()

        for i in range(args.count):
            offset = i * args.interval
            with open('binaries/' + args.filename + "_" + offset + ".headerless.bin", 'wb') as w:
                w.write(data[offset:])

if __name__ == "__main__":        
    main()