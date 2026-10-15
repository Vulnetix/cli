import time

import RPi.GPIO as GPIO

PIN = 18
T1H = 0.0008
T0H = 0.0004


def write_byte(value):
    for bit in format(value, "08b"):
        GPIO.output(PIN, GPIO.HIGH)
        time.sleep(T1H if bit == "1" else T0H)
        GPIO.output(PIN, GPIO.LOW)
