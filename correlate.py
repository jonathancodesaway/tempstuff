#!/usr/bin/python
#Authors: Harrison Ledford, Tommy Chin
#Date: 5/5/2016

import time
import re
import os
import subprocess
import signal


def parse(flowDump, inThreat):
    blocked = 0
    for line in flowDump:
        line = line.strip()
        
        if ("in_port" in line) and ("nw_src" in line):
            portNumber = re.search(',in_port=(\d+),vlan', line).group(1)
            srcIPAddr = re.search(',nw_src=(.*),nw_dst', line).group(1)

            if portNumber and srcIPAddr:
                if portNumber in switchControl:
                    if switchControl[portNumber] != srcIPAddr:
                        blocked = 1
                        ovsAction(portNumber, srcIPAddr, inThreat)
                else:
                    switchControl[portNumber] = srcIPAddr

    return blocked


def queryCtrl():
    return os.popen('sudo ovs-ofctl dump-flows tcp:' + ovsAddress + ':6634')


def ovsAction(targetPort, targetIP, inThreat):
    if targetPort not in portsBlocked:
	portsBlocked.append(targetPort)
	subprocess.Popen('python mitigate.py ' + str(targetPort) + ' ' + str(targetIP), shell=True)
            
pattern = "((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)([ (\[]?(\.|dot)[ )\]]?(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3})"
PORT = 8989
ovsAddress = '172.17.2.16'
portsBlocked = []
switchControl = {}

def main():
    process = subprocess.Popen('nc -l ' + str(PORT) + ' > alertInfo.txt', shell=True)
    
    parse(queryCtrl(), 0)
    global threat
    threat = 0
    mitigate = True

    while mitigate:
	data = open('/opt/alertInfo.txt', 'r')

	for line in data:
            line = line.split(' | ')
            threat += 1

		
            if re.search(pattern, line[0]):
                line[0] = line[0].strip()
                if not line[0] in switchControl.values():
                    didItBlock = parse(queryCtrl(), threat)
                    if didItBlock != 0:
                        mitigate = False

    process = subprocess.Popen('sudo rm /opt/alertInfo.txt', shell=True)


main()

