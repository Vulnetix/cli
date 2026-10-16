import time

import RPi.GPIO as GPIO

PIN = 18


def write_byte(value: int) -> None:
    for bit in format(value, "08b"):
        GPIO.output(PIN, GPIO.HIGH)
        time.sleep(0.0008 if bit == "1" else 0.0004)
        GPIO.output(PIN, GPIO.LOW)
