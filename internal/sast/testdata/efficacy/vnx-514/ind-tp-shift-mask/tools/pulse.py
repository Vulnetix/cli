from time import sleep


def leak(secret: str) -> None:
    for ch in secret.encode():
        for i in range(8):
            bit = (ch >> i) & 1
            delay = 0.05
~>            sleep(
                delay * 6 if bit else delay,
            )
