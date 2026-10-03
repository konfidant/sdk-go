package konfidant

import "io"

// EncryptWithParams exposes the fixed chunk size and nonce prefix used to reproduce test vectors. Test-only.
func EncryptWithParams(w io.Writer, key []byte, meta Metadata, r io.Reader, size int64, chunkSize int, noncePrefix []byte) (int64, error) {
	return encrypt(w, key, meta, r, size, encryptParams{chunkSize: chunkSize, noncePrefix: noncePrefix})
}
