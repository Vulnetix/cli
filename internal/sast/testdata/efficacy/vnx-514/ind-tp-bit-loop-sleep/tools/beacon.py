import time


def send(payload: bytes) -> None:
    for byte in payload:
        for bit in format(byte, "08b"):
~>            time.sleep(0.4 if bit == "1" else 0.1)
