#!/bin/bash
./espwrite.py
./esptool.py -p /dev/ttyAMA0 -b 115200 write_flash --flash_size=detect 0 jsonsniffer.bin
./espreset.py
