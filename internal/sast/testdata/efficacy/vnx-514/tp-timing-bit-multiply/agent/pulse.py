from time import sleep

UNIT = 0.25
BASE = 0.05


def pulse(value):
    bits = bin(value)[2:]
    for b in bits:
~>        sleep(int(b) * UNIT + BASE)
        send_heartbeat()
    for i in range(16):
~>        sleep(BASE + ((value >> i) & 1) * UNIT)
