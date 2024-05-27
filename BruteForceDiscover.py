#!/usr/bin/env python3

import argparse, subprocess, random, operator, json, multiprocessing, threading, datetime

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

def bruteforce(prefix, suffix, filename, languageId):
    cpus = multiprocessing.cpu_count() - 4
    map = []
    start = datetime.datetime.now()
    for i in range(8192):
        active = []
        for t in range(cpus): 
            x = threading.Thread(target=run_ghidra, args=(filename, languageId, prefix + ('%02x' % ((i * 8) + t)) + suffix, map))
            active.append(x)
            x.start()
        
        for t in active:
            t.join()
        if i % 64 == 0:
            print("\r%d - %d" % (i, (datetime.datetime.now() - start).total_seconds()))
    d = datetime.datetime.now()
    s = sorted(map, key=operator.itemgetter('referenced'), reverse=True)
    with open("results" + d.strftime("%Y%m%d%H%M%S") + ".json", 'w') as r:
        r.write(json.dumps(map))
    return s[0]

def main():
    parser = argparse.ArgumentParser(
        prog="BruteForceDiscover", 
        description="A script that takes raw binary programs and bruteforces their load offset")
    parser.add_argument('filename')
    parser.add_argument('languageId')

    args = parser.parse_args()
    half1 = bruteforce('', '0000', args.filename, args.languageId)
    half2 = bruteforce(half1['base'], '', args.filename, args.languageId)
    base = '0x%04x%04x' % (half1['base'] % half2['base'])
    print('Winner: ' + base)
    with open('results.txt', 'w') as r:
        r.write(base)

if __name__ == "__main__":        
    main()