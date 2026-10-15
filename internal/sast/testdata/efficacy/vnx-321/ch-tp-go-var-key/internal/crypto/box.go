package crypto

import (
	"crypto/aes"
	"crypto/cipher"
)

~>var aesKey = []byte("@@sample:t[9]Xr[4]Kq[2]Wm[7]Zp[1]Lv[8]Bn[3]Hc[6]Yd[5]Fg[0]Js[2]@@")

func newGCM() (cipher.AEAD, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
