#!/usr/bin/python
#Author: Harrison Ledford
#Date: 4/19/2016

import sys
import os
import subprocess

ovsAddress = '172.17.2.16'

os.popen('sudo ovs-ofctl add-flow tcp:' + ovsAddress + ':6634 "priority=1,in_port=' + sys.argv[1] + ',action=drop"')
print("Malicious traffic through port " + str(sys.argv[1]) + " from " + str(sys.argv[2]) + " has been dropped.")
print("Correlation and Mitigation has happened.")
