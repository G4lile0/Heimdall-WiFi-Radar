#!/usr/bin/env python

from time import sleep
import RPi.GPIO as GPIO

# declaration of chip reset pin
def GPIO_custominit():
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(17,GPIO.OUT,initial=1)
    GPIO.setup(27,GPIO.OUT,initial=1)

GPIO_custominit()

# bring GPIO 17 LOW then back up = reset
GPIO.output(17,0)
sleep(0.5)
GPIO.output(17,1)

# information for user
print "Chip has been reset"

#clean exit
GPIO.cleanup()
