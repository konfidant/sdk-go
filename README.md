# konfidant-go

[![Test](https://github.com/konfidant/sdk-go/actions/workflows/test.yml/badge.svg)](https://github.com/konfidant/sdk-go/actions/workflows/test.yml)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/95477308ce544dcd8b3c275127fef054)](https://app.codacy.com/gh/konfidant/sdk-go/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
[![Codacy Badge](https://app.codacy.com/project/badge/Coverage/95477308ce544dcd8b3c275127fef054)](https://app.codacy.com/gh/konfidant/sdk-go/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_coverage)

Official Go SDK for the [Konfidant](https://www.konfidant.app?utm_source=github&utm_medium=gosdkreadme) API (v1.1.0). Standard library only.

Konfidant lets you share secrets — text and files — through one-time links that self-destruct after being read.

---

## Zero-knowledge model

Everything is encrypted **on your machine** before it leaves it:

1. The SDK generates a fresh random 256-bit key for every share.
2. Content, file name and MIME type are encrypted with AES-256-GCM in KNF1, Konfidant's chunked encryption
   format (the same format the Konfidant web app uses; every chunk is authenticated, so modified, reordered or
   truncated data is rejected).
3. Only ciphertext is uploaded. The server returns a link carrying a single-use token:
   `https://download.konfidant.app/#t=<token>`.
4. The SDK appends the key **to the URL fragment**: `https://download.konfidant.app/#t=<token>&k=<key>`.

Browsers never send the fragment (`#…`) to a server, so Konfidant never sees the key and cannot decrypt your data.
It only learns the ciphertext size and when the share was created and opened.

> **The share link is the secret.** Anyone holding the full link can open the share (once). Send it over a
> channel you trust and never log it.

---

## Installation

```bash
go get github.com/konfidant/sdk-go
```

---

## Quick start

```go
import konfidant "github.com/konfidant/sdk-go"

client, err := konfidant.New(konfidant.ClientOptions{APIKey: os.Getenv("KONFIDANT_API_KEY")})
if err != nil {
    log.Fatal(err)
}

result, err := client.ShareText(ctx, "super-secret-password", konfidant.ShareOptions{TTLHours: 24})
if err != nil {
    log.Fatal(err)
}

fmt.Println("Share this link:", result.ShareURL)
```

### Share a file

The file is encrypted while it is streamed to storage; it is never held in memory as a whole.

```go
f, err := os.Open("report.pdf")
if err != nil {
    log.Fatal(err)
}
defer f.Close()
info, _ := f.Stat()

result, err := client.ShareFile(ctx, f, info.Size(), konfidant.FileShareOptions{
    Filename:    "report.pdf",      // encrypted, never visible to Konfidant
    ContentType: "application/pdf", // encrypted as well
    TTLHours:    72,
})
if err != nil {
    log.Fatal(err)
}

fmt.Println("Share this link:", result.ShareURL)
```

### Open a share (recipient side)

```go
opened, err := konfidant.OpenShare(ctx, shareURL) // no API key needed
if errors.Is(err, konfidant.ErrShareUnavailable) {
    log.Fatal("link already used or expired")
}
if err != nil {
    log.Fatal(err)
}

switch opened.Kind {
case konfidant.KindText:
    fmt.Println(string(opened.Data))
case konfidant.KindFile:
    _ = os.WriteFile(filepath.Base(opened.Name), opened.Data, 0o600)
}
```

Opening a share consumes it: the ciphertext can be downloaded only once.

---

## API reference

### `konfidant.New(opts ClientOptions) (*Client, error)`

| Field         | Type            | Required | Description                                                                      |
|---------------|-----------------|----------|----------------------------------------------------------------------------------|
| `APIKey`      | `string`        | Yes      | Your Konfidant API key (sent as `Authorization: Bearer …` to the API only)       |
| `BaseURL`     | `string`        | No       | API base URL (default: `https://www.konfidant.app`)                              |
| `HTTPTimeout` | `time.Duration` | No       | Per-request timeout, also bounds a whole upload (default `120s`; `-1` disables)  |

### `client.ShareText(ctx, text, ShareOptions{TTLHours}) (*ShareResult, error)`

Encrypts `text` locally and creates a one-time text share. There is no client-side size limit on text; your plan's
limits are enforced by the server.

| `ShareResult` field | Type        | Description                                                      |
|---------------------|-------------|------------------------------------------------------------------|
| `ShareURL`          | `string`    | `https://<host>/#t=<token>&k=<key>` — send this to the recipient |
| `ID`                | `string`    | Text ID (empty if your organization does not keep share records) |
| `ExpiresAt`         | `time.Time` | Expiry                                                           |

### `client.ShareFile(ctx, r, size, FileShareOptions{Filename, ContentType, TTLHours}) (*FileShareResult, error)`

Encrypts `size` bytes from `r` and shares them as a one-time file (create upload → stream ciphertext → complete).
`r` must yield exactly `size` bytes. `Filename` may be at most 1 024 UTF-8 bytes and `ContentType` at most 255.

| `FileShareResult` field | Type        | Description                                                      |
|-------------------------|-------------|------------------------------------------------------------------|
| `ShareURL`              | `string`    | `https://<host>/#t=<token>&k=<key>`                              |
| `FileID`                | `string`    | File ID (empty if your organization does not keep share records) |
| `ExpiresAt`             | `time.Time` | Expiry                                                           |
| `VerifiedBurn`          | `bool`      | Whether verified burn-on-read is enabled                         |

### Low-level file flow

`ShareFile` is built from three calls you can use directly, e.g. to upload from a pre-encrypted source:

```go
key := konfidant.GenerateKey()
meta := konfidant.Metadata{Kind: konfidant.KindFile, Name: "report.pdf", MIME: "application/pdf"}
size, err := konfidant.CiphertextSize(meta, plaintextSize)

upload, err := client.CreateFileUpload(ctx, size, 72) // POST /api/v1/files

pr, pw := io.Pipe()
go func() {
    _, err := konfidant.Encrypt(pw, key, meta, plaintext, plaintextSize)
    pw.CloseWithError(err)
}()
err = client.UploadCiphertext(ctx, upload, pr) // PUT upload_url (no Authorization header)

done, err := client.CompleteFileUpload(ctx, upload.FileKey) // POST /api/v1/files/{file_key}/complete
shareURL := done.DownloadURL + "&k=" + konfidant.EncodeKey(key)
```

`CompleteFileUpload` returns an error matching `konfidant.ErrUploadIncomplete` (HTTP 409) if the ciphertext has
not been fully uploaded.

### `client.ListShares(ctx, *ListSharesParams) (*ListSharesResponse, error)`

Lists your organization's shares. Pass `nil` for defaults. Filters: `Type` (`"file"`/`"text"`),
`Status` (`"active"`/`"accessed"`), `Limit`, `Offset`. File names are not returned: Konfidant does not know them.

### `client.OpenShare(ctx, shareURL)` / `konfidant.OpenShare(ctx, shareURL)` `(*OpenedShare, error)`

Downloads (once) and decrypts a share link. The API key is never sent. Returns `Kind`, `Name`, `MIME` and `Data`.

### KNF1 primitives

| Function                                                           | Description                                                   |
|--------------------------------------------------------------------|---------------------------------------------------------------|
| `GenerateKey() []byte`                                             | Fresh random 32-byte key                                      |
| `EncodeKey(key) string` / `DecodeKey(s) ([]byte, error)`           | Unpadded base64url (43 characters)                            |
| `CiphertextSize(meta, contentLen) (int64, error)`                  | Exact KNF1 size for a payload                                 |
| `Encrypt(w, key, meta, r, size) (int64, error)`                    | Streaming encryption, one chunk (1 MiB) in memory at a time  |
| `NewDecryptReader(key, r) (*DecryptReader, error)`                 | Streaming decryption; `Metadata()` plus `io.Reader` content   |
| `Decrypt(key, ciphertext) (*OpenedShare, error)`                   | In-memory decryption                                          |

`DecryptReader` authenticates chunk by chunk. If `Read` returns an error other than `io.EOF`, discard everything
read so far: the ciphertext was modified, truncated, or the key is wrong (`ErrDecrypt`).

---

## Error handling

API errors are `*konfidant.APIError`:

```go
_, err := client.ShareText(ctx, "secret", konfidant.ShareOptions{TTLHours: 1})

var apiErr *konfidant.APIError
if errors.As(err, &apiErr) {
    fmt.Println(apiErr.StatusCode) // e.g. 401
    fmt.Println(apiErr.Code)       // "error" field of the JSON body
    fmt.Println(apiErr.Message)    // optional "message" field
    fmt.Println(string(apiErr.Body))
}
```

| Sentinel (`errors.Is`)  | Meaning                                                            |
|-------------------------|--------------------------------------------------------------------|
| `ErrUploadIncomplete`   | 409 from `CompleteFileUpload`: ciphertext not fully uploaded       |
| `ErrShareUnavailable`   | 410 from `OpenShare`: link already used or expired                 |
| `ErrDecrypt`            | Wrong key, or modified / reordered / truncated ciphertext          |
| `ErrInvalidFormat`      | Not a KNF1 payload, or invalid metadata (e.g. file name too long)  |
| `ErrInvalidKey`         | Key is not 32 bytes / 43 base64url characters                      |

| Status | Meaning                    |
|--------|----------------------------|
| `400`  | Bad request / invalid body |
| `401`  | Missing or invalid API key |
| `403`  | Insufficient API key scope |
| `404`  | Resource not found         |

---

## Development

```bash
go test ./...        # run tests (includes the KNF1 test vectors in testdata/)
go test -race ./...  # race detector
go vet ./...         # static analysis
```
