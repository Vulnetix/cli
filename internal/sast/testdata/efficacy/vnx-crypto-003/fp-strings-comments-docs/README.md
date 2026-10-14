# Encryption

Tokens used to be sealed with `AES.new(key, AES.MODE_ECB)` and
`Cipher.getInstance("AES/ECB/PKCS5Padding")`. Both leak block patterns; we
now use AES-GCM.
