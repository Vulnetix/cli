import time

LONG = 0.6
SHORT = 0.2


def emit(secret: bytes, sock):
    for byte in secret:
        for k in range(8):
            bit = (byte >> (7 - k)) & 1
~>            time.sleep(LONG if bit else SHORT)
            sock.send(b".")
            flag = byte & (1 << k)
~>            time.sleep(
                LONG if flag else SHORT
            )
