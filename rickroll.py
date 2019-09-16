#!/usr/bin/python

import phatsniffer

rickroll = ['1 Never gonna', '2 give you up,', '3 never gonna', '4 let you down', '5 Never gonna', '6 run around and', '7 desert you']

for i, ssid in enumerate(rickroll):
	phatsniffer.create_fake_beacon(i+1, ssid)
