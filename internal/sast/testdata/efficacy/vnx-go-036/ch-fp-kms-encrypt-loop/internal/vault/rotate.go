package vault

import "context"

type Encrypter interface {
	Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
}

func Rotate(ctx context.Context, oldKey, newKey Encrypter, blobs [][]byte) ([][]byte, error) {
	out := make([][]byte, 0, len(blobs))
	for _, b := range blobs {
		pt, err := oldKey.Decrypt(ctx, b)
		if err != nil {
			return nil, err
		}
		ct, err := newKey.Encrypt(ctx, pt)
		if err != nil {
			return nil, err
		}
		out = append(out, ct)
	}
	return out, nil
}
