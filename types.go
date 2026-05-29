package konfidant

import (
	"io"
	"time"
)

// ClientOptions configures the Konfidant client.
type ClientOptions struct {
	// APIKey is your Konfidant Bearer API key (required).
	APIKey string
	// BaseURL overrides the default API base URL (optional).
	// Default: "https://www.konfidant.app"
	BaseURL string
	// HTTPTimeout overrides the per-request HTTP timeout (optional).
	// Default: 30s. Set to -1 to disable.
	HTTPTimeout time.Duration
}

// ShareTextRequest is the body for POST /api/v1/texts.
type ShareTextRequest struct {
	Text     string `json:"text"`
	TTLHours int    `json:"ttl_hours"`
}

// ShareTextResponse is returned by ShareText.
type ShareTextResponse struct {
	TextID       string `json:"text_id"`
	ShareURL     string `json:"share_url"`
	ExpiresAt    string `json:"expires_at"`
	VerifiedBurn bool   `json:"verified_burn"`
}

// ShareFileRequest is the body for POST /api/v1/files.
type ShareFileRequest struct {
	Filename string `json:"filename"`
	FileSize int64  `json:"file_size"`
	TTLHours int    `json:"ttl_hours"`
}

// FileMetadataHeaders holds the S3 metadata headers required for the PUT upload.
type FileMetadataHeaders struct {
	UserID         string `json:"x-amz-meta-user-id"`
	TTLHours       string `json:"x-amz-meta-ttl-hours"`
	OrganizationID string `json:"x-amz-meta-organization-id"`
}

// ShareFileResponse is returned by ShareFile.
type ShareFileResponse struct {
	UploadURL       string              `json:"upload_url"`
	FileKey         string              `json:"file_key"`
	MetadataHeaders FileMetadataHeaders `json:"metadata_headers"`
	PollURL         string              `json:"poll_url"`
}

// FileStatusResponse is returned by GetFileStatus.
// Check Status to distinguish "processing" from "complete".
type FileStatusResponse struct {
	Status string `json:"status"` // "processing" or "complete"

	// Set when Status == "processing"
	Message string `json:"message,omitempty"`

	// Set when Status == "complete"
	FileID       string `json:"file_id,omitempty"`
	FileName     string `json:"file_name,omitempty"`
	ShareURL     string `json:"share_url,omitempty"`
	ExpiresAt    string `json:"expires_at,omitempty"`
	VerifiedBurn bool   `json:"verified_burn,omitempty"`
}

// Share represents a single share entry returned by ListShares.
type Share struct {
	Type          string  `json:"type"`
	FileName      string  `json:"file_name"`
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

// UploadFileOptions configures a low-level UploadFile call.
type UploadFileOptions struct {
	// Reader supplies the file bytes. Must be fully readable (no partial reads).
	Reader io.Reader
	// Size is the Content-Length in bytes. Required for the S3 PUT.
	Size int64
	// ContentType is the MIME type (e.g. "application/pdf").
	ContentType string
	// Presigned is the full response from ShareFile.
	Presigned ShareFileResponse
}

// ShareResult is returned by ShareAndUploadFile.
type ShareResult struct {
	ShareURL     string `json:"share_url"`
	FileID       string `json:"file_id"`
	ExpiresAt    string `json:"expires_at"`
	VerifiedBurn bool   `json:"verified_burn"`
}
