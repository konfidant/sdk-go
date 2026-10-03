package konfidant_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"testing/iotest"

	konfidant "github.com/konfidant/sdk-go"
)

type knfVector struct {
	Name           string `json:"name"`
	KeyHex         string `json:"key_hex"`
	KeyB64URL      string `json:"key_b64url"`
	NoncePrefixHex string `json:"nonce_prefix_hex"`
	ChunkSize      int    `json:"chunk_size"`
	Kind           string `json:"kind"`
	FileName       string `json:"file_name"`
	MIME           string `json:"mime"`
	PlaintextHex   string `json:"plaintext_hex"`
	CiphertextHex  string `json:"ciphertext_hex"`
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

func loadVectors(t *testing.T) []knfVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/knf1-test-vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var file struct {
		Format  string      `json:"format"`
		Vectors []knfVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if file.Format != "KNF1" || len(file.Vectors) == 0 {
		t.Fatalf("unexpected vector file: format=%q vectors=%d", file.Format, len(file.Vectors))
	}
	return file.Vectors
}

func vectorMeta(t *testing.T, v knfVector) konfidant.Metadata {
	t.Helper()
	switch v.Kind {
	case "text":
		return konfidant.Metadata{Kind: konfidant.KindText}
	case "file":
		return konfidant.Metadata{Kind: konfidant.KindFile, Name: v.FileName, MIME: v.MIME}
	}
	t.Fatalf("unknown kind %q", v.Kind)
	return konfidant.Metadata{}
}

var testKey = bytes.Repeat([]byte{7}, konfidant.KeySize)

func encryptBytes(t *testing.T, key []byte, meta konfidant.Metadata, content []byte, chunkSize int) []byte {
	t.Helper()
	var buf bytes.Buffer
	n, err := konfidant.EncryptWithParams(&buf, key, meta, bytes.NewReader(content), int64(len(content)), chunkSize, nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if n != int64(buf.Len()) {
		t.Fatalf("written %d, buffer %d", n, buf.Len())
	}
	return buf.Bytes()
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// ---------------------------------------------------------------------------
// Test vectors
// ---------------------------------------------------------------------------

func TestVectors_EncryptByteForByte(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			key := mustHex(t, v.KeyHex)
			plaintext := mustHex(t, v.PlaintextHex)
			want := mustHex(t, v.CiphertextHex)
			meta := vectorMeta(t, v)

			if got := konfidant.EncodeKey(key); got != v.KeyB64URL {
				t.Fatalf("EncodeKey = %q, want %q", got, v.KeyB64URL)
			}
			var buf bytes.Buffer
			n, err := konfidant.EncryptWithParams(&buf, key, meta, bytes.NewReader(plaintext), int64(len(plaintext)),
				v.ChunkSize, mustHex(t, v.NoncePrefixHex))
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			if !bytes.Equal(buf.Bytes(), want) {
				t.Fatalf("ciphertext mismatch (got %d bytes, want %d)", buf.Len(), len(want))
			}
			if n != int64(len(want)) {
				t.Fatalf("written = %d, want %d", n, len(want))
			}
			if v.ChunkSize == konfidant.DefaultChunkSize {
				size, err := konfidant.CiphertextSize(meta, int64(len(plaintext)))
				if err != nil || size != int64(len(want)) {
					t.Fatalf("CiphertextSize = %d, %v; want %d", size, err, len(want))
				}
			}
		})
	}
}

func TestVectors_Decrypt(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			key, err := konfidant.DecodeKey(v.KeyB64URL)
			if err != nil {
				t.Fatalf("DecodeKey: %v", err)
			}
			if !bytes.Equal(key, mustHex(t, v.KeyHex)) {
				t.Fatal("DecodeKey mismatch")
			}
			ciphertext := mustHex(t, v.CiphertextHex)
			want := vectorMeta(t, v)

			got, err := konfidant.Decrypt(key, ciphertext)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if got.Kind != want.Kind || got.Name != want.Name || got.MIME != want.MIME {
				t.Fatalf("metadata = %v/%q/%q, want %v/%q/%q", got.Kind, got.Name, got.MIME, want.Kind, want.Name, want.MIME)
			}
			if !bytes.Equal(got.Data, mustHex(t, v.PlaintextHex)) {
				t.Fatal("plaintext mismatch")
			}

			// Streaming: one byte at a time exercises the "last chunk" look-ahead rule.
			r, err := konfidant.NewDecryptReader(key, iotest.OneByteReader(bytes.NewReader(ciphertext)))
			if err != nil {
				t.Fatalf("NewDecryptReader: %v", err)
			}
			if r.Metadata() != want {
				t.Fatalf("streaming metadata = %+v, want %+v", r.Metadata(), want)
			}
			data, err := io.ReadAll(iotest.OneByteReader(r))
			if err != nil || !bytes.Equal(data, mustHex(t, v.PlaintextHex)) {
				t.Fatalf("streaming decrypt: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Round trips
// ---------------------------------------------------------------------------

func TestRoundTrip_Sizes(t *testing.T) {
	const cs = konfidant.MinChunkSize
	meta := konfidant.Metadata{Kind: konfidant.KindFile, Name: "data.bin", MIME: "application/octet-stream"}
	prefix := 4 + 5 + len(meta.Name) + len(meta.MIME)
	sizes := []int{0, 1, cs - prefix - 1, cs - prefix, cs - prefix + 1, 2*cs - prefix, 3*cs - prefix + 17, 5 * cs}
	for _, size := range sizes {
		content := randomBytes(t, size)
		ciphertext := encryptBytes(t, testKey, meta, content, cs)
		got, err := konfidant.Decrypt(testKey, ciphertext)
		if err != nil {
			t.Fatalf("size %d: Decrypt: %v", size, err)
		}
		if got.Kind != konfidant.KindFile || got.Name != meta.Name || got.MIME != meta.MIME || !bytes.Equal(got.Data, content) {
			t.Fatalf("size %d: round trip mismatch", size)
		}
		r, err := konfidant.NewDecryptReader(testKey, iotest.HalfReader(bytes.NewReader(ciphertext)))
		if err != nil {
			t.Fatalf("size %d: NewDecryptReader: %v", size, err)
		}
		if data, err := io.ReadAll(r); err != nil || !bytes.Equal(data, content) {
			t.Fatalf("size %d: streaming round trip: %v", size, err)
		}
	}
}

func TestRoundTrip_DefaultChunkMultiChunk(t *testing.T) {
	content := randomBytes(t, 2*konfidant.DefaultChunkSize+12345)
	meta := konfidant.Metadata{Kind: konfidant.KindFile, Name: "big.bin"}
	var buf bytes.Buffer
	n, err := konfidant.Encrypt(&buf, testKey, meta, bytes.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	size, _ := konfidant.CiphertextSize(meta, int64(len(content)))
	if n != size || int64(buf.Len()) != size {
		t.Fatalf("size: written %d, buffer %d, CiphertextSize %d", n, buf.Len(), size)
	}
	if !bytes.Equal(buf.Bytes()[:4], []byte("KNF1")) {
		t.Fatal("missing magic")
	}
	got, err := konfidant.Decrypt(testKey, buf.Bytes())
	if err != nil || !bytes.Equal(got.Data, content) {
		t.Fatalf("Decrypt: %v", err)
	}
}

func TestRoundTrip_Text(t *testing.T) {
	text := strings.Repeat("héllo wörld ", 100000) // no size limit on text
	var buf bytes.Buffer
	if _, err := konfidant.Encrypt(&buf, testKey, konfidant.Metadata{Kind: konfidant.KindText}, strings.NewReader(text), int64(len(text))); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := konfidant.Decrypt(testKey, buf.Bytes())
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got.Kind != konfidant.KindText || got.Kind.String() != "text" || string(got.Data) != text {
		t.Fatal("text round trip mismatch")
	}
}

func TestEncrypt_FreshNoncePrefix(t *testing.T) {
	meta := konfidant.Metadata{Kind: konfidant.KindText}
	a := encryptBytes(t, testKey, meta, []byte("same"), 0)
	b := encryptBytes(t, testKey, meta, []byte("same"), 0)
	if bytes.Equal(a[8:15], b[8:15]) || bytes.Equal(a, b) {
		t.Fatal("nonce prefix must be random per encryption")
	}
}

// ---------------------------------------------------------------------------
// Tampering, truncation, wrong key
// ---------------------------------------------------------------------------

func multiChunkCiphertext(t *testing.T) ([]byte, []byte) {
	t.Helper()
	content := randomBytes(t, 3*konfidant.MinChunkSize) // 4 chunks with the metadata prefix
	return encryptBytes(t, testKey, konfidant.Metadata{Kind: konfidant.KindFile, Name: "x"}, content, konfidant.MinChunkSize), content
}

func expectDecryptErr(t *testing.T, name string, key, ciphertext []byte, target error) {
	t.Helper()
	if _, err := konfidant.Decrypt(key, ciphertext); !errors.Is(err, target) {
		t.Fatalf("%s: Decrypt err = %v, want %v", name, err, target)
	}
	// The streaming reader must fail too, either up front or while reading.
	r, err := konfidant.NewDecryptReader(key, iotest.OneByteReader(bytes.NewReader(ciphertext)))
	if err == nil {
		_, err = io.ReadAll(r)
	}
	if !errors.Is(err, target) {
		t.Fatalf("%s: streaming err = %v, want %v", name, err, target)
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	ciphertext, _ := multiChunkCiphertext(t)
	wrong := bytes.Repeat([]byte{8}, konfidant.KeySize)
	expectDecryptErr(t, "wrong key", wrong, ciphertext, konfidant.ErrDecrypt)
}

func TestDecrypt_Tampered(t *testing.T) {
	ciphertext, _ := multiChunkCiphertext(t)
	sealed := konfidant.MinChunkSize + konfidant.TagSize
	positions := map[string]int{
		"nonce prefix":     9,
		"first chunk":      konfidant.HeaderSize + 3,
		"first chunk tag":  konfidant.HeaderSize + sealed - 1,
		"middle chunk":     konfidant.HeaderSize + sealed + 100,
		"last chunk":       len(ciphertext) - konfidant.TagSize - 1,
		"last chunk tag":   len(ciphertext) - 1,
		"chunk size field": 6, // 4096 -> 4352: still in range, caught by AAD and framing
	}
	for name, pos := range positions {
		bad := bytes.Clone(ciphertext)
		bad[pos] ^= 0x01
		expectDecryptErr(t, name, testKey, bad, konfidant.ErrDecrypt)
	}
}

func TestDecrypt_ReorderedChunks(t *testing.T) {
	ciphertext, _ := multiChunkCiphertext(t)
	sealed := konfidant.MinChunkSize + konfidant.TagSize
	c1 := ciphertext[konfidant.HeaderSize+sealed : konfidant.HeaderSize+2*sealed]
	c2 := ciphertext[konfidant.HeaderSize+2*sealed : konfidant.HeaderSize+3*sealed]
	bad := bytes.Clone(ciphertext)
	copy(bad[konfidant.HeaderSize+sealed:], c2)
	copy(bad[konfidant.HeaderSize+2*sealed:], c1)
	expectDecryptErr(t, "swapped chunks", testKey, bad, konfidant.ErrDecrypt)

	dup := bytes.Clone(ciphertext)
	copy(dup[konfidant.HeaderSize+2*sealed:], c1)
	expectDecryptErr(t, "duplicated chunk", testKey, dup, konfidant.ErrDecrypt)
}

func TestDecrypt_Truncated(t *testing.T) {
	ciphertext, _ := multiChunkCiphertext(t)
	sealed := konfidant.MinChunkSize + konfidant.TagSize
	cases := map[string]int{
		"at chunk boundary":       konfidant.HeaderSize + 2*sealed, // full chunks only: last flag check must fail
		"after first chunk":       konfidant.HeaderSize + sealed,
		"mid chunk":               konfidant.HeaderSize + sealed + 500,
		"one byte short":          len(ciphertext) - 1,
		"only tag of last chunk":  konfidant.HeaderSize + 3*sealed + konfidant.TagSize,
		"header plus a few bytes": konfidant.HeaderSize + 5,
		"header only":             konfidant.HeaderSize,
	}
	for name, n := range cases {
		expectDecryptErr(t, name, testKey, ciphertext[:n], konfidant.ErrDecrypt)
	}
	expectDecryptErr(t, "partial header", testKey, ciphertext[:10], konfidant.ErrInvalidFormat)
	expectDecryptErr(t, "empty", testKey, nil, konfidant.ErrInvalidFormat)
}

func TestDecrypt_ExtraTrailingData(t *testing.T) {
	ciphertext, _ := multiChunkCiphertext(t)
	expectDecryptErr(t, "trailing byte", testKey, append(bytes.Clone(ciphertext), 0), konfidant.ErrDecrypt)
}

func TestDecrypt_BadHeader(t *testing.T) {
	ciphertext := encryptBytes(t, testKey, konfidant.Metadata{Kind: konfidant.KindText}, []byte("hi"), 0)
	cases := map[string]func([]byte){
		"magic":           func(b []byte) { b[0] = 'X' },
		"reserved":        func(b []byte) { b[15] = 1 },
		"chunk too small": func(b []byte) { copy(b[4:8], []byte{0, 0, 0x0f, 0xff}) },
		"chunk too large": func(b []byte) { copy(b[4:8], []byte{0x01, 0, 0, 0x01}) },
	}
	for name, mutate := range cases {
		bad := bytes.Clone(ciphertext)
		mutate(bad)
		expectDecryptErr(t, name, testKey, bad, konfidant.ErrInvalidFormat)
	}
}

func TestDecrypt_SourceErrorPropagates(t *testing.T) {
	ciphertext, _ := multiChunkCiphertext(t)
	boom := errors.New("network down")
	src := io.MultiReader(bytes.NewReader(ciphertext[:konfidant.HeaderSize+10000]), iotest.ErrReader(boom))
	r, err := konfidant.NewDecryptReader(testKey, src)
	if err != nil {
		t.Fatalf("NewDecryptReader: %v", err)
	}
	if _, err := io.ReadAll(r); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
	if _, err := r.Read(make([]byte, 1)); !errors.Is(err, boom) {
		t.Fatalf("error must be sticky, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Encrypt input validation & metadata limits
// ---------------------------------------------------------------------------

func TestEncrypt_MetadataLimits(t *testing.T) {
	ok := []konfidant.Metadata{
		{Kind: konfidant.KindFile, Name: strings.Repeat("n", konfidant.MaxNameBytes), MIME: strings.Repeat("m", konfidant.MaxMIMEBytes)},
		{Kind: konfidant.KindFile},
		{Kind: konfidant.KindText},
	}
	for _, meta := range ok {
		ciphertext := encryptBytes(t, testKey, meta, []byte("x"), 0)
		got, err := konfidant.Decrypt(testKey, ciphertext)
		if err != nil || got.Name != meta.Name || got.MIME != meta.MIME {
			t.Fatalf("meta %v: %v", meta.Kind, err)
		}
		size, err := konfidant.CiphertextSize(meta, 1)
		if err != nil || size != int64(len(ciphertext)) {
			t.Fatalf("CiphertextSize = %d, %v; want %d", size, err, len(ciphertext))
		}
	}

	bad := map[string]konfidant.Metadata{
		"name too long":  {Kind: konfidant.KindFile, Name: strings.Repeat("n", konfidant.MaxNameBytes+1)},
		"mime too long":  {Kind: konfidant.KindFile, MIME: strings.Repeat("m", konfidant.MaxMIMEBytes+1)},
		"text with name": {Kind: konfidant.KindText, Name: "a.txt"},
		"text with mime": {Kind: konfidant.KindText, MIME: "text/plain"},
		"unknown kind":   {Kind: 3},
		"invalid utf-8":  {Kind: konfidant.KindFile, Name: "\xff"},
	}
	for name, meta := range bad {
		if _, err := konfidant.Encrypt(io.Discard, testKey, meta, strings.NewReader("x"), 1); !errors.Is(err, konfidant.ErrInvalidFormat) {
			t.Fatalf("%s: Encrypt err = %v", name, err)
		}
		if _, err := konfidant.CiphertextSize(meta, 1); !errors.Is(err, konfidant.ErrInvalidFormat) {
			t.Fatalf("%s: CiphertextSize err = %v", name, err)
		}
	}
	// Name limit is in bytes, not characters.
	multibyte := konfidant.Metadata{Kind: konfidant.KindFile, Name: strings.Repeat("é", konfidant.MaxNameBytes/2+1)}
	if _, err := konfidant.CiphertextSize(multibyte, 1); !errors.Is(err, konfidant.ErrInvalidFormat) {
		t.Fatalf("multibyte name: err = %v", err)
	}
}

func TestEncrypt_SizeMismatch(t *testing.T) {
	meta := konfidant.Metadata{Kind: konfidant.KindFile, Name: "f"}
	if _, err := konfidant.Encrypt(io.Discard, testKey, meta, strings.NewReader("abc"), 4); err == nil || !strings.Contains(err.Error(), "shorter") {
		t.Fatalf("short reader: err = %v", err)
	}
	if _, err := konfidant.Encrypt(io.Discard, testKey, meta, strings.NewReader("abcde"), 4); err == nil || !strings.Contains(err.Error(), "longer") {
		t.Fatalf("long reader: err = %v", err)
	}
	if _, err := konfidant.Encrypt(io.Discard, testKey, meta, strings.NewReader(""), -1); !errors.Is(err, konfidant.ErrInvalidFormat) {
		t.Fatalf("negative size: err = %v", err)
	}
	if _, err := konfidant.Encrypt(io.Discard, []byte("short"), meta, strings.NewReader("a"), 1); !errors.Is(err, konfidant.ErrInvalidKey) {
		t.Fatalf("bad key: err = %v", err)
	}
	if _, err := konfidant.EncryptWithParams(io.Discard, testKey, meta, strings.NewReader("a"), 1, 100, nil); !errors.Is(err, konfidant.ErrInvalidFormat) {
		t.Fatalf("bad chunk size: err = %v", err)
	}
}

func TestEncrypt_WriterError(t *testing.T) {
	boom := errors.New("disk full")
	w := &failingWriter{after: 2, err: boom}
	content := randomBytes(t, 3*konfidant.MinChunkSize)
	_, err := konfidant.EncryptWithParams(w, testKey, konfidant.Metadata{Kind: konfidant.KindFile}, bytes.NewReader(content), int64(len(content)), konfidant.MinChunkSize, nil)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
}

type failingWriter struct {
	after int
	err   error
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.after == 0 {
		return 0, w.err
	}
	w.after--
	return len(p), nil
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

func TestKeys(t *testing.T) {
	a, b := konfidant.GenerateKey(), konfidant.GenerateKey()
	if len(a) != konfidant.KeySize || bytes.Equal(a, b) {
		t.Fatal("GenerateKey must return fresh 32-byte keys")
	}
	enc := konfidant.EncodeKey(a)
	if len(enc) != 43 || strings.ContainsAny(enc, "+/=") {
		t.Fatalf("EncodeKey = %q, want 43 unpadded base64url chars", enc)
	}
	dec, err := konfidant.DecodeKey(enc)
	if err != nil || !bytes.Equal(dec, a) {
		t.Fatalf("DecodeKey round trip: %v", err)
	}
	for _, bad := range []string{"", enc[:42], enc + "A", enc[:42] + "=", enc[:42] + "+", strings.Repeat("!", 43)} {
		if _, err := konfidant.DecodeKey(bad); !errors.Is(err, konfidant.ErrInvalidKey) {
			t.Fatalf("DecodeKey(%q) err = %v", bad, err)
		}
	}
	if konfidant.Kind(9).String() != "unknown" || konfidant.KindFile.String() != "file" {
		t.Fatal("Kind.String")
	}
}
