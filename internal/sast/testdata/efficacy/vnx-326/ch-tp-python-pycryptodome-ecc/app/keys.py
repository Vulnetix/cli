from Crypto.PublicKey import ECC


def device_key():
~>    return ECC.generate(curve="P-192")


def legacy_key():
~>    key = ECC.generate(curve='secp192r1')
    return key.export_key(format="PEM")
