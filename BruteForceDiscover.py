#!/usr/bin/env python3

import argparse, subprocess, random, operator, json, multiprocessing, threading, datetime, math

def run_ghidra(filename, languageId, address, map):
    n = ( '%030x' % random.randrange(16**30))
    cmd = '/opt/ghidra-11.0.3/support/analyzeHeadless /tmp ' + n + ' -max-cpu 1 -import ' + filename + ' -postScript CountReferencedStrings.java -processor ' + languageId + ' -loader BinaryLoader -loader-baseAddr ' + address + ' -deleteProject | grep CountReferencedStrings.java'
    output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)
    referenced = output[output.find("<referenced>") + len("<referenced>"):output.find("</referenced>")]
    total = output[output.find("<total>") + len("<total>"):output.find("</total>")]
    referenced = int(referenced)
    total = int(total)
    e = {'base': address, 'total': total, 'referenced': referenced}
    map.append(e)
    with open("results/results-%04x.txt" % (address), 'w') as r:
        r.write(json.dumps(e))

def bruteforce(prefix, suffix, filename, languageId, start):
    if not start:
        start = 0
    cpus = multiprocessing.cpu_count() - 4
    if cpus <= 0:
        cpus = 1
    map = []
    start = datetime.datetime.now()
    for i in range(math.ceil(65536 / cpus) - start):
        active = []
        for t in range(cpus): 
            x = threading.Thread(target=run_ghidra, args=(filename, languageId, prefix + ('%04x' % (((i * cpus) + t) + start)) + suffix, map))
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
    parser.add_argument('-s', '--start', type=int)

    args = parser.parse_args()
    half1 = bruteforce('', '0000', args.filename, args.languageId, args.start)
    base = '0x%04x0000' % (half1['base'])
    print('Winner: ' + base)
    with open('results/winner.txt', 'w') as r:
        r.write(base)

if __name__ == "__main__":        
    main()