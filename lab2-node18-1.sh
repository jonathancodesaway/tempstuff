#!/bin/bash

ifconfig wlan0 down

sleep 5

read MAC

airodump-ng -c 11 --bssid $MAC --output-format pcap -w wlan-capture mon0