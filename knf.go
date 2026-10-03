package konfidant

// KNF1 — Konfidant client-side encryption format.
//
// Content is encrypted on the sender's machine with AES-256-GCM using a fresh random 256-bit key per share. The
// key only ever travels in the share link's URL fragment, so Konfidant's servers store and deliver ciphertext they
// cannot decrypt. The payload is chunked using the STREAM construction (per-chunk nonce = random prefix, chunk
// index and a "last chunk" flag), which prevents reordering, duplication and truncation of chunks.
//
// Layout: header (16 bytes, AAD of every chunk) || sealed_chunk_0 || … || sealed_chunk_n, where the chunked
// plaintext stream is uint32_be(len(meta)) || meta || content and
// meta = kind (1) || uint16_be(len(name)) || name || uint16_be(len(mime)) || mime.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// KNF1 format constants.
const (
	// KeySize is the size of a share key in bytes (AES-256).
	KeySize = 32
	// HeaderSize is the size of the plaintext KNF1 header.
	HeaderSize = 16
	// TagSize is the size of the AES-GCM authentication tag appended to every chunk.
	TagSize = 16
	// NoncePrefixSize is the size of the random per-share nonce prefix.
	NoncePrefixSize = 7
	// DefaultChunkSize is the number of plaintext bytes per chunk used by Encrypt.
	DefaultChunkSize = 1 << 20
	// MinChunkSize is the smallest chunk size a valid KNF1 header may declare.
	MinChunkSize = 4096
	// MaxChunkSize is the largest chunk size a valid KNF1 header may declare.
	MaxChunkSize = 16 << 20
	// MaxNameBytes is the maximum length of a file name, in UTF-8 bytes.
	MaxNameBytes = 1024
	// MaxMIMEBytes is the maximum length of a MIME type, in UTF-8 bytes.
	MaxMIMEBytes = 255
)

const (
	metaFixedSize    = 5 // kind (1) + name length (2) + mime length (2)
	metaLengthPrefix = 4
	maxMetaSize      = metaFixedSize + 2*0xffff
	maxChunkCount    = 1 << 32
	encodedKeyLength = 43
)

var knfMagic = [4]byte{'K', 'N', 'F', '1'}

var (
	// ErrInvalidFormat is returned when a payload is not well-formed KNF1 (bad header, metadata or inputs).
	ErrInvalidFormat = errors.New("konfidant: invalid KNF1 payload")
	// ErrDecrypt is returned when a chunk fails authentication: wrong key, or modified, reordered or truncated
	// ciphertext. Any plaintext already read from a DecryptReader must then be discarded.
	ErrDecrypt = errors.New("konfidant: decryption failed: wrong key or corrupted or truncated ciphertext")
	// ErrInvalidKey is returned for keys that are not 32 bytes or not 43 characters of unpadded base64url.
	ErrInvalidKey = errors.New("konfidant: invalid key")
)

// Kind is the type of content carried by a KNF1 payload.
type Kind uint8

const (
	// KindText marks a text share.
	KindText Kind = 1
	// KindFile marks a file share.
	KindFile Kind = 2
)

// String returns "text", "file" or "unknown".
func (k Kind) String() string {
	switch k {
	case KindText:
		return "text"
	case KindFile:
		return "file"
	default:
		return "unknown"
	}
}

// Metadata is the encrypted metadata stored inside a KNF1 payload.
type Metadata struct {
	Kind Kind
	// Name is the original file name (files only, at most MaxNameBytes UTF-8 bytes).
	Name string
	// MIME is the content type (files only, at most MaxMIMEBytes UTF-8 bytes, may be empty).
	MIME string
}

// GenerateKey returns a fresh random 32-byte share key. Never reuse a key for two shares.
func GenerateKey() []byte {
	key := make([]byte, KeySize)
	_, _ = rand.Read(key) // crypto/rand.Read never fails (it crashes the program instead)
	return key
}

// EncodeKey encodes a key as unpadded base64url (43 characters), the form used in share links.
func EncodeKey(key []byte) string {
	return base64.RawURLEncoding.EncodeToString(key)
}

// DecodeKey decodes a 43-character unpadded base64url key.
func DecodeKey(encoded string) ([]byte, error) {
	if len(encoded) != encodedKeyLength {
		return nil, fmt.Errorf("%w: expected %d base64url characters", ErrInvalidKey, encodedKeyLength)
	}
	key, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(key) != KeySize {
		return nil, fmt.Errorf("%w: malformed base64url", ErrInvalidKey)
	}
	return key, nil
}

func (m Metadata) encode() ([]byte, error) {
	switch m.Kind {
	case KindText:
		if m.Name != "" || m.MIME != "" {
			return nil, fmt.Errorf("%w: text shares must not carry a name or MIME type", ErrInvalidFormat)
		}
	case KindFile:
	default:
		return nil, fmt.Errorf("%w: unknown content kind %d", ErrInvalidFormat, m.Kind)
	}
	if len(m.Name) > MaxNameBytes {
		return nil, fmt.Errorf("%w: file name exceeds %d bytes", ErrInvalidFormat, MaxNameBytes)
	}
	if len(m.MIME) > MaxMIMEBytes {
		return nil, fmt.Errorf("%w: MIME type exceeds %d bytes", ErrInvalidFormat, MaxMIMEBytes)
	}
	if !utf8.ValidString(m.Name) || !utf8.ValidString(m.MIME) {
		return nil, fmt.Errorf("%w: name and MIME type must be valid UTF-8", ErrInvalidFormat)
	}
	out := make([]byte, 0, metaFixedSize+len(m.Name)+len(m.MIME))
	out = append(out, byte(m.Kind))
	out = binary.BigEndian.AppendUint16(out, uint16(len(m.Name)))
	out = append(out, m.Name...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(m.MIME)))
	out = append(out, m.MIME...)
	return out, nil
}

func decodeMetadata(b []byte) (Metadata, error) {
	if len(b) < metaFixedSize {
		return Metadata{}, fmt.Errorf("%w: metadata truncated", ErrInvalidFormat)
	}
	kind := Kind(b[0])
	if kind != KindText && kind != KindFile {
		return Metadata{}, fmt.Errorf("%w: unknown content kind", ErrInvalidFormat)
	}
	nameLen := int(binary.BigEndian.Uint16(b[1:3]))
	if 3+nameLen+2 > len(b) {
		return Metadata{}, fmt.Errorf("%w: metadata truncated", ErrInvalidFormat)
	}
	mimeLen := int(binary.BigEndian.Uint16(b[3+nameLen:]))
	if metaFixedSize+nameLen+mimeLen != len(b) {
		return Metadata{}, fmt.Errorf("%w: metadata length mismatch", ErrInvalidFormat)
	}
	name := b[3 : 3+nameLen]
	mime := b[metaFixedSize+nameLen:]
	if !utf8.Valid(name) || !utf8.Valid(mime) {
		return Metadata{}, fmt.Errorf("%w: metadata is not valid UTF-8", ErrInvalidFormat)
	}
	return Metadata{Kind: kind, Name: string(name), MIME: string(mime)}, nil
}

// CiphertextSize returns the exact KNF1 size, in bytes, that Encrypt produces for meta and contentLen bytes of
// content. It validates meta the same way Encrypt does.
func CiphertextSize(meta Metadata, contentLen int64) (int64, error) {
	encoded, err := meta.encode()
	if err != nil {
		return 0, err
	}
	if contentLen < 0 {
		return 0, fmt.Errorf("%w: negative content size", ErrInvalidFormat)
	}
	return ciphertextSize(len(encoded), contentLen, DefaultChunkSize), nil
}

func ciphertextSize(metaLen int, contentLen int64, chunkSize int) int64 {
	stream := int64(metaLengthPrefix+metaLen) + contentLen
	chunks := (stream + int64(chunkSize) - 1) / int64(chunkSize)
	return HeaderSize + stream + TagSize*chunks
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("%w: key must be %d bytes", ErrInvalidKey, KeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func chunkNonce(dst *[12]byte, prefix []byte, index uint64, last bool) []byte {
	copy(dst[:NoncePrefixSize], prefix)
	binary.BigEndian.PutUint32(dst[NoncePrefixSize:], uint32(index))
	dst[11] = 0
	if last {
		dst[11] = 1
	}
	return dst[:]
}

// encryptParams overrides chunk size and nonce prefix. Only tests set them.
type encryptParams struct {
	chunkSize   int
	noncePrefix []byte
}

// Encrypt reads exactly size bytes of content from r, encrypts them with meta under key in the KNF1 format and
// writes the ciphertext to w, chunk by chunk (at most one chunk is held in memory). It returns the number of bytes
// written, which equals CiphertextSize(meta, size) on success. It fails if r yields fewer or more than size bytes.
func Encrypt(w io.Writer, key []byte, meta Metadata, r io.Reader, size int64) (int64, error) {
	return encrypt(w, key, meta, r, size, encryptParams{})
}

func encrypt(w io.Writer, key []byte, meta Metadata, r io.Reader, size int64, p encryptParams) (int64, error) {
	chunkSize := p.chunkSize
	if chunkSize == 0 {
		chunkSize = DefaultChunkSize
	}
	if chunkSize < MinChunkSize || chunkSize > MaxChunkSize {
		return 0, fmt.Errorf("%w: chunk size out of range", ErrInvalidFormat)
	}
	noncePrefix := p.noncePrefix
	if noncePrefix == nil {
		noncePrefix = make([]byte, NoncePrefixSize)
		_, _ = rand.Read(noncePrefix)
	}
	if len(noncePrefix) != NoncePrefixSize {
		return 0, fmt.Errorf("%w: nonce prefix must be %d bytes", ErrInvalidFormat, NoncePrefixSize)
	}
	if size < 0 {
		return 0, fmt.Errorf("%w: negative content size", ErrInvalidFormat)
	}
	encodedMeta, err := meta.encode()
	if err != nil {
		return 0, err
	}
	aead, err := newAEAD(key)
	if err != nil {
		return 0, err
	}

	prefix := binary.BigEndian.AppendUint32(make([]byte, 0, metaLengthPrefix+len(encodedMeta)), uint32(len(encodedMeta)))
	prefix = append(prefix, encodedMeta...)

	var header [HeaderSize]byte
	copy(header[:4], knfMagic[:])
	binary.BigEndian.PutUint32(header[4:8], uint32(chunkSize))
	copy(header[8:15], noncePrefix)

	streamLen := int64(len(prefix)) + size
	chunkCount := (streamLen + int64(chunkSize) - 1) / int64(chunkSize)
	if chunkCount > maxChunkCount {
		return 0, fmt.Errorf("%w: content too large", ErrInvalidFormat)
	}

	written := int64(0)
	n, err := w.Write(header[:])
	written += int64(n)
	if err != nil {
		return written, err
	}

	chunk := make([]byte, min(int64(chunkSize), streamLen))
	sealed := make([]byte, 0, len(chunk)+TagSize)
	var nonce [12]byte
	for i := int64(0); i < chunkCount; i++ {
		start := i * int64(chunkSize)
		end := min(start+int64(chunkSize), streamLen)
		buf := chunk[:end-start]
		off := 0
		if i == 0 {
			// chunkSize >= 4096 and metadata is at most 1 288 bytes, so the prefix always fits in chunk 0.
			off = copy(buf, prefix)
		}
		if _, err := io.ReadFull(r, buf[off:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return written, fmt.Errorf("konfidant: content is shorter than the declared size of %d bytes", size)
			}
			return written, err
		}
		last := i == chunkCount-1
		if last {
			// Reject oversized input before the final chunk is emitted, so an upload never completes with it.
			var probe [1]byte
			if n, err := io.ReadFull(r, probe[:]); n > 0 {
				return written, fmt.Errorf("konfidant: content is longer than the declared size of %d bytes", size)
			} else if err != nil && !errors.Is(err, io.EOF) {
				return written, err
			}
		}
		sealed = aead.Seal(sealed[:0], chunkNonce(&nonce, noncePrefix, uint64(i), last), buf, header[:])
		n, err := w.Write(sealed)
		written += int64(n)
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

// DecryptReader decrypts a KNF1 stream incrementally. Metadata is available as soon as NewDecryptReader returns;
// Read yields the content.
//
// Chunks are authenticated one at a time, so Read may return plaintext before a later chunk fails to
// authenticate. If Read returns any error other than io.EOF, all content read so far must be discarded.
type DecryptReader struct {
	src        io.Reader
	aead       cipher.AEAD
	header     [HeaderSize]byte
	chunkSize  int
	sealed     []byte // up to one sealed chunk plus one byte of look-ahead
	sealedLen  int
	plain      []byte // reusable plaintext buffer
	pending    []byte // plaintext not yet returned by Read
	index      uint64
	done       bool // the final chunk has been opened
	err        error
	meta       Metadata
	nonceBytes [12]byte
}

// NewDecryptReader reads and validates the KNF1 header from r, decrypts the chunk(s) carrying the metadata and
// returns a reader for the content.
func NewDecryptReader(key []byte, r io.Reader) (*DecryptReader, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	d := &DecryptReader{src: r, aead: aead}
	if _, err := io.ReadFull(r, d.header[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("%w: ciphertext truncated", ErrInvalidFormat)
		}
		return nil, err
	}
	if !bytes.Equal(d.header[:4], knfMagic[:]) || d.header[15] != 0 {
		return nil, fmt.Errorf("%w: bad header", ErrInvalidFormat)
	}
	chunkSize := binary.BigEndian.Uint32(d.header[4:8])
	if chunkSize < MinChunkSize || chunkSize > MaxChunkSize {
		return nil, fmt.Errorf("%w: chunk size out of range", ErrInvalidFormat)
	}
	d.chunkSize = int(chunkSize)
	d.sealed = make([]byte, d.chunkSize+TagSize+1)
	d.plain = make([]byte, 0, d.chunkSize)

	// The metadata always lies in chunk 0 for payloads produced by a conforming encoder, but parse it from the
	// stream so that a (still authenticated) payload spreading it over several chunks is accepted as well.
	if err := d.nextChunk(); err != nil {
		return nil, err
	}
	stream := d.pending
	for {
		if len(stream) >= metaLengthPrefix {
			metaLen := binary.BigEndian.Uint32(stream)
			if metaLen > maxMetaSize {
				return nil, fmt.Errorf("%w: metadata too large", ErrInvalidFormat)
			}
			if total := metaLengthPrefix + int(metaLen); len(stream) >= total {
				meta, err := decodeMetadata(stream[metaLengthPrefix:total])
				if err != nil {
					return nil, err
				}
				d.meta = meta
				d.pending = stream[total:]
				return d, nil
			}
		}
		if d.done {
			return nil, fmt.Errorf("%w: metadata truncated", ErrInvalidFormat)
		}
		stream = bytes.Clone(stream) // d.plain is reused by the next chunk
		if err := d.nextChunk(); err != nil {
			return nil, err
		}
		stream = append(stream, d.pending...)
	}
}

// Metadata returns the decrypted metadata.
func (d *DecryptReader) Metadata() Metadata { return d.meta }

// Read implements io.Reader over the decrypted content.
func (d *DecryptReader) Read(p []byte) (int, error) {
	for len(d.pending) == 0 {
		if d.err != nil {
			return 0, d.err
		}
		if d.done {
			return 0, io.EOF
		}
		if err := d.nextChunk(); err != nil {
			d.err = err
			return 0, err
		}
	}
	n := copy(p, d.pending)
	d.pending = d.pending[n:]
	return n, nil
}

// nextChunk opens the next sealed chunk into d.pending. A full-size chunk is opened as non-final only once at
// least one more byte has arrived; at end of input the buffered remainder is opened as the final chunk.
func (d *DecryptReader) nextChunk() error {
	sealedSize := d.chunkSize + TagSize
	n, err := io.ReadFull(d.src, d.sealed[d.sealedLen:])
	d.sealedLen += n
	switch {
	case err == nil:
		if err := d.open(d.sealed[:sealedSize], false); err != nil {
			return err
		}
		d.sealed[0] = d.sealed[sealedSize]
		d.sealedLen = 1
		return nil
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
		if d.sealedLen <= TagSize {
			return ErrDecrypt // truncated: no room for a non-empty final chunk
		}
		if err := d.open(d.sealed[:d.sealedLen], true); err != nil {
			return err
		}
		d.sealedLen = 0
		d.done = true
		return nil
	default:
		return err
	}
}

func (d *DecryptReader) open(sealed []byte, last bool) error {
	if d.index >= maxChunkCount {
		return ErrDecrypt
	}
	nonce := chunkNonce(&d.nonceBytes, d.header[8:15], d.index, last)
	plain, err := d.aead.Open(d.plain[:0], nonce, sealed, d.header[:])
	if err != nil {
		return ErrDecrypt
	}
	d.pending = plain
	d.index++
	return nil
}

// Decrypt decrypts a complete in-memory KNF1 payload.
func Decrypt(key, ciphertext []byte) (*OpenedShare, error) {
	return decryptFrom(key, bytes.NewReader(ciphertext))
}

func decryptFrom(key []byte, r io.Reader) (*OpenedShare, error) {
	d, err := NewDecryptReader(key, r)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(d)
	if err != nil {
		return nil, err
	}
	return &OpenedShare{Kind: d.meta.Kind, Name: d.meta.Name, MIME: d.meta.MIME, Data: data}, nil
}
