package keystore

// KDFParams is the on-disk description of how a key file was derived; the
// salt is public by design and must be stored with the ciphertext.
type KDFParams struct {
	Salt       []byte `json:"salt"`
	Iterations int    `json:"iterations"`
	KeyLen     int    `json:"keylen"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password" validate:"required"`
}
