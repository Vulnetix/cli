from Crypto.Cipher import AES

SECRET_KEY = "@@sample:0[1]23[4]56[7]89[a]bc[d]ef[0]12[3]45[6]78[9]ab[c]de[f]@@"
cipher = AES.new(b"0123456789abcdef", AES.MODE_ECB)
