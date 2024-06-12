#!/usr/bin/env python3

import argparse, subprocess, random, operator, json, multiprocessing, threading, datetime, math, pathlib, hashlib

def run_ghidra(filename, languageId, address, map, idx, hash):
    p = pathlib.Path("results/" + hash + '/' + str(idx) + "/results-%08x.json" % (address))
    if p.exists():
        with open(p, 'r') as f:
            map.append(json.loads(f.read()))
        return
    
    n = ( '%030x' % random.randrange(16**30))
    cmd = 'timeout -k 60 600 /opt/ghidra-11.0.3/support/analyzeHeadless /tmp ' + n + ' -max-cpu 1 -import ' + filename + ' -postScript CountReferencedStrings.java -processor "' + languageId + '" -loader BinaryLoader -loader-baseAddr ' + hex(address).replace('0x', '') + ' -deleteProject | grep CountReferencedStrings.java'
    output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
    referenced = output[output.find("<referenced>") + len("<referenced>"):output.find("</referenced>")]
    total = output[output.find("<total>") + len("<total>"):output.find("</total>")]
    referenced = int(referenced)
    total = int(total)
    e = {'base': address, 'total': total, 'referenced': referenced, 'offset': idx }
    map.append(e)
    with open(p, 'w') as r:
        r.write(json.dumps(e))

def bruteforce(startIdx, end, filename, languageId, interval, idx, hash):
    cpus = multiprocessing.cpu_count()
    map = []
    start = datetime.datetime.now()
    for i in range(math.ceil((((end) - (startIdx)) / interval) / cpus)):
        active = []
        for t in range(cpus): 
            x = threading.Thread(target=run_ghidra, args=(filename, languageId, (startIdx + (i * interval * cpus) + (t * interval)), map, idx, hash))
            active.append(x)
            x.start()
        
        for t in active:
            t.join()
        print("\r%d - %d" % (i, (datetime.datetime.now() - start).total_seconds()))
    d = datetime.datetime.now()
    s = sorted(map, key=operator.itemgetter('referenced'), reverse=True)
    return s[0]

def main():
    parser = argparse.ArgumentParser(
        prog="BruteForceDiscover", 
        description="A script that takes raw binary programs and bruteforces their load offset")
    parser.add_argument('filename')
    parser.add_argument('languageId')
    parser.add_argument('-s', '--start', type=lambda x: int(x, 16), default=0, const=0, nargs='?')
    parser.add_argument('-e', '--end', type=lambda x: int(x, 16), default=0xffffffff, const=0xffffffff, nargs='?')
    parser.add_argument('-i', '--interval', type=lambda x: int(x, 16), default=0x10000, const=0x10000, nargs='?')
    parser.add_argument('-x', '--index', type=lambda x: int(x, 16), default=0, const=0, nargs='?')

    args = parser.parse_args()
    with open(args.filename, 'rb') as f:
        h = hashlib.sha256()
        h.update(f.read())
        hash = h.hexdigest()
    pathlib.Path("results/" + hash + '/' + str(args.index)).mkdir(parents=True, exist_ok=True)
    half1 = bruteforce(args.start, args.end, args.filename, args.languageId, args.interval, args.index, hash)
    base = '0x%08x' % (half1['base'])
    print('Winner: ' + base)
    with open('results/winner.txt', 'w') as r:
        r.write(base)

if __name__ == "__main__":        
    main()