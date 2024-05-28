#!/usr/bin/env python3

import argparse, subprocess, random, operator, json

def main():

    parser = argparse.ArgumentParser(
        prog="AnalyzeBFResults", 
        description="A script that takes the bruteforce results and displays the 10 most likely base address objects in json format.")
    parser.add_argument('filename')
    args = parser.parse_args()
    
    with open(args.filename, 'r') as f:
        j = json.loads(f.read())
        s = sorted(j, key=operator.itemgetter('referenced'), reverse=True)
        print(json.dumps(s[:10]))

if __name__ == "__main__":
    main()