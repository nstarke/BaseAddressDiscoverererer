#!/usr/bin/env python3

import argparse, glob, operator, json

def main():
    results = []
    for file in glob.glob("results/results-*.txt"):
        with open(file, 'r') as f:
            j = json.loads(f.read())
            j['base'] = '%04x0000' % (j['base'])
            results.append(j)

    s = sorted(results, key=operator.itemgetter('referenced'), reverse=True)
    print(json.dumps(s[:10]))
            

if __name__ == "__main__":
    main()