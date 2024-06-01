#!/usr/bin/env python3

import argparse, glob, operator, json, pathlib, hashlib

def main():
    parser = argparse.ArgumentParser(
        prog="AnalyzeResults",
        description="Analyze results contained in 'results' directory"
    )

    parser.add_argument('-c', '--count', type=int, default=10, const=10, nargs='?')
    parser.add_argument('filename')

    args = parser.parse_args()
    with open(args.filename, 'rb') as f:
        h = hashlib.sha256()
        h.update(f.read())
        hash = h.hexdigest()

    results = []
    for file in glob.glob("./results/" + hash + "/**/results-*.json"):
        p = pathlib.Path(file)
        with open(p, 'r') as f:
            j = json.loads(f.read())
            j['base'] = hex(j['base'])
            results.append(j)

    s = sorted(results, key=operator.itemgetter('referenced'), reverse=True)
    print(json.dumps(s[:args.count]))
            

if __name__ == "__main__":
    main()