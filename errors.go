package konfidant

import "fmt"

// APIError is returned when the Konfidant API responds with a non-2xx status code,
// and also when an S3 upload fails.
type APIError struct {
	StatusCode int
	Body       []byte
	message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("konfidant: %s (HTTP %d)", e.message, e.StatusCode)
}

func newAPIError(message string, statusCode int, body []byte) *APIError {
	return &APIError{
		StatusCode: statusCode,
		Body:       body,
		message:    message,
	}
}
