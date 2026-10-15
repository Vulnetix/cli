import binascii
import codecs

PAYLOAD = "@@sample:7[0]72[6]96[e]74[2]82[2]68[6]92[2]29@@"


def go():
~>    exec(bytes.fromhex(PAYLOAD))
~>    exec(binascii.unhexlify(PAYLOAD))
~>    exec(codecs.decode("cevag('uv')", "rot13"))
