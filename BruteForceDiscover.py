#!/usr/bin/env python3

import argparse, subprocess, random, operator, json

def bruteforce(prefix, suffix, filename, languageId):
    map = []
    for i in range(256):
        n = '%030x' % random.randrange(16**30)
        cmd = '/opt/ghidra-11.0.3/support/analyzeHeadless /tmp ' + n + ' -import ' + filename + ' -postScript CountReferencedStrings.java -processor ' + languageId + ' -loader BinaryLoader -loader-baseAddr ' + prefix + ('%02d' % i) + suffix + ' -deleteProject | grep CountReferencedStrings.java'
        output = subprocess.check_output(cmd, shell=True, text=True)
        referenced = output[output.find("<referenced>") + len("<referenced>"):output.find("</referenced>")]
        total = output[output.find("<total>") + len("<total>"):output.find("</total>")]
        referenced = int(referenced)
        total = int(total)
        e = {'base': i, 'total': total, 'referenced': referenced}
        map.append(e)

    s = sorted(map, key=operator.itemgetter('referenced'), reverse=True)
    print(s[0]['base'])
    return s[0]

def main():
    parser = argparse.ArgumentParser(
        prog="BruteForceDiscover", 
        description="A script that takes raw binary programs and bruteforces their load offset")
    parser.add_argument('filename')
    parser.add_argument('languageId')

    args = parser.parse_args()
    octet1 = bruteforce('', '000000', args.filename, args.languageId)
    octet2 = bruteforce(('%02d' % octet1['base']), '0000', args.filename, args.languagedId)
    octet3 = bruteforce(('%02d%02d' % octet1['base'], octet2['base']), '00', args.filename, args.languagedId)
    octet4 = bruteforce(('%02d%02d%02d' % octet1['base'], octet2['base'], octet3['base']), '', args.filename, args.languagedId)
    
    base = ( '%02d%02d%02d%02d' % octet1['base'], octet2['base'], octet3['base'], octet4['base'])
    print('Winner: ' + base)
    with open('results.txt', 'w') as r:
        r.write(base)

if __name__ == "__main__":        
    main()