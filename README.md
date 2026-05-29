# konfidant-go

[![Test](https://github.com/konfidant/sdk-go/actions/workflows/test.yml/badge.svg)](https://github.com/konfidant/sdk-go/actions/workflows/test.yml)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/95477308ce544dcd8b3c275127fef054)](https://app.codacy.com/gh/konfidant/sdk-go/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
[![Codacy Badge](https://app.codacy.com/project/badge/Coverage/95477308ce544dcd8b3c275127fef054)](https://app.codacy.com/gh/konfidant/sdk-go/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_coverage)

Official Go SDK for the [Konfidant](https://www.konfidant.app) API.

Konfidant lets you share secrets — encrypted text and files — that self-destruct after being read.

---

## Installation

```bash
go get github.com/konfidant/sdk-go
```

---

## Quick start

```go
import konfidant "github.com/konfidant/sdk-go"

client, err := konfidant.New(konfidant.ClientOptions{APIKey: "your-api-key"})
if err != nil {
    log.Fatal(err)
}

result, err := client.ShareText(ctx, konfidant.ShareTextRequest{
    Text:     "super-secret-password",
    TTLHours: 24,
})
if err != nil {
    log.Fatal(err)
}

fmt.Println("Share this link:", result.ShareURL)
```

---

## Authentication

All requests require a Bearer API key. Generate one from the Konfidant dashboard.

```go
client, err := konfidant.New(konfidant.ClientOptions{
    APIKey: os.Getenv("KONFIDANT_API_KEY"),
})
```

---

## API Reference

### `konfidant.New(opts)`

| Field          | Type            | Required | Description                                                    |
|----------------|-----------------|----------|----------------------------------------------------------------|
| `APIKey`       | `string`        | Yes      | Your Konfidant API key                                         |
| `BaseURL`      | `string`        | No       | Override the base URL (default: `https://www.konfidant.app`)   |
| `HTTPTimeout`  | `time.Duration` | No       | Per-request HTTP timeout (default: `30s`; set `-1` to disable) |

Returns `(*Client, error)`. Error if `APIKey` is empty.

---

### `client.ShareText(ctx, req)`

Encrypt and share a text message.

**Request: `ShareTextRequest`**

| Field      | Type     | Description              |
|------------|----------|--------------------------|
| `Text`     | `string` | The secret text to share |
| `TTLHours` | `int`    | Time-to-live in hours    |

**Response: `*ShareTextResponse`**

| Field          | Type     | Description                                 |
|----------------|----------|---------------------------------------------|
| `TextID`       | `string` | Unique ID of the shared text                |
| `ShareURL`     | `string` | One-time download link to send to recipient |
| `ExpiresAt`    | `string` | Expiry datetime                             |
| `VerifiedBurn` | `bool`   | Whether burn-on-read is verified            |

---

### `client.ShareFile(ctx, req)`

Requests a presigned upload URL for a file. Use the returned response with `UploadFile`
to complete the upload, then poll `GetFileStatus` for the share link.

> For a one-call convenience wrapper, see `ShareAndUploadFile`.

**Request: `ShareFileRequest`**

| Field      | Type     | Description                      |
|------------|----------|----------------------------------|
| `Filename` | `string` | Original filename with extension |
| `FileSize` | `int64`  | File size in bytes               |
| `TTLHours` | `int`    | Time-to-live in hours            |

**Response: `*ShareFileResponse`**

| Field             | Type                  | Description                                  |
|-------------------|-----------------------|----------------------------------------------|
| `UploadURL`       | `string`              | Short-lived presigned S3 PUT URL             |
| `FileKey`         | `string`              | Use with `GetFileStatus` and `UploadFile`    |
| `PollURL`         | `string`              | Convenience URL for status polling           |
| `MetadataHeaders` | `FileMetadataHeaders` | Required S3 headers — passed by `UploadFile` |

---

### `client.UploadFile(ctx, opts)`

Upload file bytes to the presigned S3 URL from `ShareFile`. Automatically attaches required S3 metadata headers. Does NOT send the Konfidant Authorization header to S3.

**Options: `UploadFileOptions`**

| Field         | Type               | Description                        |
|---------------|--------------------|------------------------------------|
| `Reader`      | `io.Reader`        | File content                       |
| `Size`        | `int64`            | Content-Length in bytes            |
| `ContentType` | `string`           | MIME type (e.g. `application/pdf`) |
| `Presigned`   | `ShareFileResponse`| Full response from `ShareFile`     |

**Example: manual three-step flow**

```go
f, _ := os.Open("report.pdf")
defer f.Close()
info, _ := f.Stat()

presigned, err := client.ShareFile(ctx, konfidant.ShareFileRequest{
    Filename: "report.pdf",
    FileSize: info.Size(),
    TTLHours: 72,
})

err = client.UploadFile(ctx, konfidant.UploadFileOptions{
    Reader:      f,
    Size:        info.Size(),
    ContentType: "application/pdf",
    Presigned:   *presigned,
})

// Poll until complete
for {
    status, err := client.GetFileStatus(ctx, presigned.FileKey)
    if status.Status == "complete" {
        fmt.Println("Share URL:", status.ShareURL)
        break
    }
    time.Sleep(2 * time.Second)
}
```

---

### `client.GetFileStatus(ctx, fileKey)`

Poll the encryption status of an uploaded file.

| Argument  | Type     | Description                                 |
|-----------|----------|---------------------------------------------|
| `fileKey` | `string` | The `FileKey` from the `ShareFile` response |

**Response: `*FileStatusResponse`**

| Field          | Type     | When set                                |
|----------------|----------|-----------------------------------------|
| `Status`       | `string` | Always (`"processing"` or `"complete"`) |
| `Message`      | `string` | When `processing`                       |
| `FileID`       | `string` | When `complete`                         |
| `FileName`     | `string` | When `complete`                         |
| `ShareURL`     | `string` | When `complete`                         |
| `ExpiresAt`    | `string` | When `complete`                         |
| `VerifiedBurn` | `bool`   | When `complete`                         |

---

### `client.ListShares(ctx, params)`

List all shares for the authenticated organization. Pass `nil` for `params` to use defaults.

**Params: `*ListSharesParams`**

| Field    | Type     | Description                |
|----------|----------|----------------------------|
| `Type`   | `string` | `"file"` or `"text"`       |
| `Status` | `string` | `"active"` or `"accessed"` |
| `Limit`  | `int`    | Page size (default 50)     |
| `Offset` | `int`    | Pagination offset          |

**Response: `*ListSharesResponse`**

```go
type ListSharesResponse struct {
    Shares     []Share
    Pagination Pagination
}
```

---

### `client.ShareAndUploadFile(ctx, r, size, filename, contentType, ttlHours, pollInterval, timeout)`

Convenience wrapper that calls `ShareFile` → `UploadFile` → polls `GetFileStatus` until complete.

| Argument       | Type            | Default | Description                           |
|----------------|-----------------|---------|---------------------------------------|
| `r`            | `io.Reader`     | —       | File content                          |
| `size`         | `int64`         | —       | File size in bytes                    |
| `filename`     | `string`        | —       | Filename with extension               |
| `contentType`  | `string`        | —       | MIME type                             |
| `ttlHours`     | `int`           | —       | Time-to-live in hours                 |
| `pollInterval` | `time.Duration` | `2s`    | How often to check status (0 = 2s)    |
| `timeout`      | `time.Duration` | `60s`   | Max wait time for encryption (0 = 60s)|

Returns `(*ShareResult, error)`. Returns an error containing `"timed out"` if encryption does not complete within
`timeout`.

**Example**

```go
f, _ := os.Open("confidential.zip")
defer f.Close()
info, _ := f.Stat()

result, err := client.ShareAndUploadFile(
    ctx,
    f,
    info.Size(),
    "confidential.zip",
    "application/zip",
    48,
    0, 0, // use defaults
)

fmt.Println("Ready to share:", result.ShareURL)
```

---

## Error handling

All API errors return `*APIError`.

```go
import "errors"

_, err := client.ShareText(ctx, konfidant.ShareTextRequest{Text: "secret", TTLHours: 1})

var apiErr *konfidant.APIError

if errors.As(err, &apiErr) {
    fmt.Println(apiErr.Error())      // e.g. "konfidant: Missing or invalid Authorization header. (HTTP 401)"
    fmt.Println(apiErr.StatusCode)   // e.g. 401
    fmt.Println(string(apiErr.Body)) // raw response body
}
```

### Common error codes

| Status | Meaning                    |
|--------|----------------------------|
| `400`  | Bad request / invalid body |
| `401`  | Missing or invalid API key |
| `403`  | Insufficient API key scope |
| `404`  | Resource not found         |

---

## Development

```bash
go test ./...        # run tests
go test -v ./...     # verbose
go test -race ./...  # race detector
go vet ./...         # static analysis
```
