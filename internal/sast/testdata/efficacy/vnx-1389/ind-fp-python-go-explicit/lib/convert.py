import ipaddress

def to_int(text):
    return int(text, 10)

def hexval(text):
    return int(text, 16)

def ip(text):
    return ipaddress.ip_address(text)

# int(x, 0) would guess the radix; we do not use it
