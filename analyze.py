#!/usr/bin/python
#Authors: Harrison Ledford, Xenia Mountrouidou
#Date: 5/5/2016

import os
import re
import subprocess
import fnmatch


def extractIPs(fileContents):
    pattern = "((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)([ (\[]?(\.|dot)[ )\]]?(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))" \
              "{3})"
    IPs = [each[0] for each in re.findall(pattern, fileContents)]
    for item in IPs:
        location = IPs.index(item)
        IP = re.sub("[ ()\[\]]", "", item)
        IP = re.sub("dot", ".", IP)
        IPs.remove(item)
        IPs.insert(location, IP)
    return IPs


def extractSequence(fileContents):
    pattern = "seq [0-9]+,"
    sequenceTemplate = re.findall(pattern, fileContents)
    if not sequenceTemplate:
        return 0
    else:
        words = sequenceTemplate[0].split()
        return words[1].strip(',')


def extractWindowSize(fileContents):
    pattern = "win [0-9]+,"
    windowTemplate = re.findall(pattern, fileContents)
    if not windowTemplate:
        return 0
    else:
        words = windowTemplate[0].split()
        return words[1].strip(',')


def extractAddress(fileContents):
    pattern = "N[1-3][1-5].[0-9]+ > N11.5001:"
    addressTemplate = re.findall(pattern, fileContents)
    if not addressTemplate:
        return 0
    else:
        return '10.10.10.' + str(addressTemplate[0][1:3])


def find(pattern, path):
    result = []
    for root, dirs, files in os.walk(path):
        for name in files:
            if fnmatch.fnmatch(name, pattern):
                result.append(os.path.join(root, name))
    return result


process = subprocess.Popen('sudo chmod 777 /var/log/snort/*', shell=True)
alertFile = '/var/log/snort/alert'
alerts = open(alertFile, 'r')

statResults = os.stat(alertFile)
statSize = statResults[6]
alerts.seek(statSize)

HOST = '172.17.2.2'
PORT = 8989

flag = True
attempts = 0
process = subprocess.Popen('> alertInfo.txt', shell=True)

while flag or attempts < 5:
    alertLocation = alerts.tell()
    line = alerts.readline()

    if not line:
        alerts.seek(alertLocation)
        
    else:
        flag = False

        results = find('snort.log.*', '/var/log/snort/')
        sortedResults = sorted(results)
        newest = sortedResults[len(results) - 2]

        process = subprocess.Popen('sudo tcpdump -n -r ' + newest + ' > output.txt', shell=True)
        process.wait()
        outputFile = open('output.txt', 'r')


        for outputLine in outputFile:
            addresses = extractIPs(outputLine)
            if addresses and addresses[0] != '0.0.0.0' and outputLine.find('[S]'):

                sequenceNumber = extractSequence(outputLine)
                windowSize = extractWindowSize(outputLine)

                process = subprocess.Popen('echo \'' + str(addresses[0]) + ' | ' + str(sequenceNumber) + ' | ' + str(windowSize) +
                                           '\' >> alertInfo.txt', shell=True)

                process = subprocess.Popen('cat /opt/alertInfo.txt | nc ' + HOST + ' ' + str(PORT) + ' -q 10', shell=True)

            if extractAddress(outputLine) and outputLine.find('[S]'):


                sequenceNumber = extractSequence(outputLine)
                windowSize = extractWindowSize(outputLine)

                process = subprocess.Popen('echo \'' + addresses[0] + ' | ' + sequenceNumber + ' | ' + windowSize +
                                           '\' >> alertInfo.txt', shell=True)

                process = subprocess.Popen('cat alertInfo.txt | nc ' + HOST + ' ' + str(PORT) + ' -q 10', shell=True)

	attempts += 1

alerts.close()
outputFile.close()
process = subprocess.Popen('sudo rm /opt/alertInfo.txt', shell=True)
process = subprocess.Popen('sudo rm /opt/output.txt', shell=True)

