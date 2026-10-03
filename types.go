package konfidant

import "time"

// ClientOptions configures the Konfidant client.
type ClientOptions struct {
	// APIKey is your Konfidant Bearer API key (required).
	APIKey string
	// BaseURL overrides the default API base URL (optional).
	// Default: "https://www.konfidant.app"
	BaseURL string
	// HTTPTimeout overrides the per-request HTTP timeout, which also bounds a whole file upload (optional).
	// Default: 120s. Set to -1 to disable.
	HTTPTimeout time.Duration
}

// ShareOptions configures ShareText.
type ShareOptions struct {
	// TTLHours is the share's time-to-live in hours. Zero lets the server apply its default.
	TTLHours int
}

// ShareResult is returned by ShareText.
type ShareResult struct {
	// ShareURL is the link to send to the recipient. It carries the decryption key in its fragment, so treat it as
	// the secret itself.
	ShareURL string
	// ID is the text's ID, or empty when the organization does not store share records.
	ID        string
	ExpiresAt time.Time
}

// FileShareOptions configures ShareFile.
type FileShareOptions struct {
	// Filename is the original file name (at most MaxNameBytes UTF-8 bytes). It is encrypted with the content.
	Filename string
	// ContentType is the MIME type (at most MaxMIMEBytes UTF-8 bytes, may be empty). It is encrypted as well.
	ContentType string
	// TTLHours is the share's time-to-live in hours. Zero lets the server apply its default.
	TTLHours int
}

// FileShareResult is returned by ShareFile.
type FileShareResult struct {
	// ShareURL is the link to send to the recipient. It carries the decryption key in its fragment, so treat it as
	// the secret itself.
	ShareURL string
	// FileID is the file's ID, or empty when the organization does not store share records.
	FileID       string
	ExpiresAt    time.Time
	VerifiedBurn bool
}

// FileUpload is returned by CreateFileUpload and describes where to PUT the ciphertext.
type FileUpload struct {
	UploadURL string `json:"upload_url"`
	FileKey   string `json:"file_key"`
	// UploadHeaders must be sent verbatim with the PUT request.
	UploadHeaders map[string]string `json:"upload_headers"`
	// UploadExpiresIn is the validity of UploadURL, in seconds.
	UploadExpiresIn int `json:"upload_expires_in"`
	// CiphertextSize is the size passed to CreateFileUpload; UploadCiphertext sends exactly this many bytes.
	CiphertextSize int64 `json:"-"`
}

// CompletedUpload is returned by CompleteFileUpload.
type CompletedUpload struct {
	// DownloadURL is the server-issued link carrying the single-use token ("https://<host>/#t=<token>"). Append
	// "&k=" + EncodeKey(key) to obtain the share link.
	DownloadURL  string    `json:"download_url"`
	FileID       string    `json:"file_id"`
	ExpiresAt    time.Time `json:"expires_at"`
	VerifiedBurn bool      `json:"verified_burn"`
}

// OpenedShare is a decrypted share, returned by OpenShare and Decrypt.
type OpenedShare struct {
	Kind Kind
	// Name is the original file name (files only).
	Name string
	// MIME is the content type (files only, may be empty).
	MIME string
	// Data is the file content, or the UTF-8 text.
	Data []byte
}

// Share represents a single share entry returned by ListShares.
type Share struct {
	Type          string  `json:"type"`
	FileSizeBytes int64   `json:"file_size_bytes"`
	CreatedAt     string  `json:"created_at"`
	ExpiresAt     string  `json:"expires_at"`
	AccessedAt    *string `json:"accessed_at"`
	CreatedBy     string  `json:"created_by"`
}

// Pagination holds page metadata returned by ListShares.
type Pagination struct {
	Total   int  `json:"total"`
	Limit   int  `json:"limit"`
	Offset  int  `json:"offset"`
	HasMore bool `json:"has_more"`
}

// ListSharesResponse is returned by ListShares.
type ListSharesResponse struct {
	Shares     []Share    `json:"shares"`
	Pagination Pagination `json:"pagination"`
}

// ListSharesParams holds optional filters for ListShares.
type ListSharesParams struct {
	Type   string // "file" or "text"
	Status string // "active" or "accessed"
	Limit  int
	Offset int
}
