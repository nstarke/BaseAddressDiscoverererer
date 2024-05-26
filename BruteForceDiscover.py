#!/usr/bin/env python3

import argparse, subprocess, random, operator, json

def main():
    parser = argparse.ArgumentParser(
        prog="BruteForceDiscover", 
        description="A script that takes raw binary programs and bruteforces their load offset")
    parser.add_argument('filename')

    args = parser.parse_args()
    map = dict()
    for i in range(65535):
        n = '%030x' % random.randrange(16**30)
        cmd = '/opt/ghidra-11.0.3/support/analyzeHeadless /tmp ' + n + ' -import ' + args.filename + ' -postScript CountReferencedStrings.java -processor "ARM:LE:32:Cortex" -loader BinaryLoader -loader-baseAddr ' + hex(i) + '0000 -delete | grep CountReferencedStrings.java'
        output = subprocess.check_output(cmd, shell=True, text=True)
        referenced = output[output.find("<referenced>") + len("<referenced>"):output.find("</referenced>")]
        total = output[output.find("<total>") + len("<total>"):output.find("</total>")]
        referenced = int(referenced)
        total = int(total)
        e = {'base': i, 'total': total, 'referenced': referenced}
        map[i] = e
    
    s = sorted(map, key=operator.itemgetter('referenced'), reverse=True)
    winner = s[0]
    print(winner)
    with open('results.json', 'w') as r:
        r.write(json.dumps(s))

if __name__ == "__main__":        
    main()