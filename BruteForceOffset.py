#!/usr/bin/env python3

import argparse, pathlib, BruteForceAddress, operator, json, hashlib

def main():
    parser = argparse.ArgumentParser(
        prog="BruteForceOffset",
        description="Divide firmware into n sized chunks to use with BruteForceAddress.py"
    )

    parser.add_argument('filename')
    parser.add_argument('languageId')
    parser.add_argument('-a', '--address', type=lambda x: int(x, 16), default=0x10, const=0x10, nargs='?')
    parser.add_argument('-c', '--count' , type=lambda x: int(x, 16), default=0x20, const=0x20, nargs='?')
    parser.add_argument('-s', '--start', type=lambda x: int(x, 16), default=0, const=0, nargs='?')
    parser.add_argument('-e', '--end', type=lambda x: int(x, 16), default=0x10000, const=0x10000, nargs='?')
    parser.add_argument('-i', '--interval', type=lambda x: int(x, 16), default=0x10000, const=0x10000, nargs='?')

    args = parser.parse_args() 
    p = pathlib.Path(args.filename)
    with open(p, 'rb') as f:
        data = f.read()
        h = hashlib.sha256()
        h.update(data)
        hash = h.hexdigest()
        pathlib.Path("results/" + hash).mkdir(parents=True, exist_ok=True)
        pathlib.Path("binaries/" + hash).mkdir(parents=True, exist_ok=True)
        for i in range(args.count):
            offset = i * args.address
            check = pathlib.Path('binaries/' + hash + '/' + p.name + "_" + str(offset) + ".headerless.bin")
            if check.exists():
                continue
            with open(check, 'wb') as w:
                w.write(data[offset:])
        results = []
        for i in range(args.count):
            offset = i * args.address
            winner = BruteForceAddress.bruteforce(args.start, args.end, 'binaries/' + hash + '/' + p.name + "_" + str(offset) + ".headerless.bin", args.languageId, args.interval, offset, hash)
            e = {
                'offset': offset, 
                'result': winner['base'], 
                'referenced': winner['referenced'], 
                'total' : winner['total'],
                'firmware': p.name 
                }
            results.append(e)
            
        s = sorted(results, key=operator.itemgetter('referenced'), reverse=True)
        print("Winner: " + json.dumps(s[0]))
        with open('results/offset-winners.json', 'w') as r:
            r.write(json.dumps(s))

if __name__ == "__main__":        
    main()