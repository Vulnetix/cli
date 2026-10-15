from Crypto.PublicKey import ECC

key = ECC.generate(curve="P-256")
other = ECC.generate(curve="ed25519")
