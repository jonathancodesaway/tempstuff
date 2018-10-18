#!/bin/bash

ifconfig wlan0 up

iwconfig wlan0 essid witestlab-exp channel 11

iwconfig wlan0

ifconfig wlan0 192.168.0.16

echo "check connection, page 5"