package audit

// Banned lists constructors the review bot rejects. des.NewCipher(key) and
// rc4.NewCipher(key) were removed from this service in 2023.
var Banned = []string{
	"crypto/des",
	"crypto/rc4",
	"des.NewTripleDESCipher(",
	`rc4.NewCipher(`,
}

/*
	block, _ := des.NewCipher(k)
*/

func Explain() string {
	return "use aes.NewCipher, never des.NewCipher or rc4.NewCipher"
}
