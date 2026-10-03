package konfidant

import (
	"errors"
	"fmt"
	"net/http"
)

var (
	// ErrUploadIncomplete matches (via errors.Is) the 409 "upload_incomplete" error from CompleteFileUpload:
	// the ciphertext has not been fully uploaded yet.
	ErrUploadIncomplete = errors.New("konfidant: upload incomplete")
	// ErrShareUnavailable matches (via errors.Is) the 410 response from OpenShare: the share was already opened or
	// has expired.
	ErrShareUnavailable = errors.New("konfidant: share already opened or expired")
)

// APIError is returned when the Konfidant API (or the upload storage) responds with a non-2xx status code.
type APIError struct {
	// StatusCode is the HTTP status code.
	StatusCode int
	// Code is the "error" field of the JSON error body, if any (e.g. "upload_incomplete").
	Code string
	// Message is the optional "message" field of the JSON error body.
	Message string
	// Body is the raw response body.
	Body []byte

	summary string
}

func (e *APIError) Error() string {
	msg := e.summary
	if e.Code != "" {
		msg = e.Code
		if e.Message != "" {
			msg += ": " + e.Message
		}
	}
	return fmt.Sprintf("konfidant: %s (HTTP %d)", msg, e.StatusCode)
}

// Is lets errors.Is match ErrUploadIncomplete and ErrShareUnavailable.
func (e *APIError) Is(target error) bool {
	switch target {
	case ErrUploadIncomplete:
		return e.StatusCode == http.StatusConflict && e.Code == "upload_incomplete"
	case ErrShareUnavailable:
		return e.StatusCode == http.StatusGone
	}
	return false
}
