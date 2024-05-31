#!/usr/bin/env python3

import argparse, glob, operator, json, pathlib

def main():
    results = []
    for file in glob.glob("results/**/results-*.json"):
        p = pathlib.Path(file)
        with open(p, 'r') as f:
            j = json.loads(f.read())
            j['base'] = hex(j['base'])
            results.append(j)

    s = sorted(results, key=operator.itemgetter('referenced'), reverse=True)
    print(json.dumps(s[:10]))
            

if __name__ == "__main__":
    main()