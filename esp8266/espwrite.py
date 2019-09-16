#!/usr/bin/env python

from time import sleep
import RPi.GPIO as GPIO

# declaration of chip reset and program pins
def GPIO_custominit():
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(17,GPIO.OUT,initial=1)
    GPIO.setup(27,GPIO.OUT,initial=1)

GPIO_custominit()

# bringing chip into program mode
GPIO.output(17,0)
sleep(0.5)
GPIO.output(27,0)
sleep(0.5)
GPIO.output(17,1)
sleep(0.5)
GPIO.output(27,1)
sleep(0.5)

# information for user
print "Chip is in write mode"

# clean exit
GPIO.cleanup()
