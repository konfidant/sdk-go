package konfidant_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	konfidant "github.com/konfidant/sdk-go"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newTestServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *konfidant.Client) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := konfidant.New(konfidant.ClientOptions{APIKey: "test-key", BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv, c
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func makeSigned() konfidant.ShareFileResponse {
	return konfidant.ShareFileResponse{
		UploadURL: "PLACEHOLDER", // overridden per test
		FileKey:   "abc123.zip",
		PollURL:   "https://www.konfidant.app/api/v1/files/abc123.zip/status",
		MetadataHeaders: konfidant.FileMetadataHeaders{
			UserID:         "user-1",
			TTLHours:       "48",
			OrganizationID: "org-1",
		},
	}
}

// ---------------------------------------------------------------------------
// New / constructor
// ---------------------------------------------------------------------------

func TestNew_MissingAPIKey(t *testing.T) {
	_, err := konfidant.New(konfidant.ClientOptions{})
	if err == nil {
		t.Fatal("expected error for missing APIKey")
	}
	if !strings.Contains(err.Error(), "APIKey is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNew_DefaultBaseURL(t *testing.T) {
	c, err := konfidant.New(konfidant.ClientOptions{APIKey: "k"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Just verify it was created without error; base URL is internal.
	_ = c
}

func TestNew_StripTrailingSlash(t *testing.T) {
	// Should not panic or fail; trailing slash stripped internally.
	_, err := konfidant.New(konfidant.ClientOptions{APIKey: "k", BaseURL: "https://example.com/"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestNew_CustomHTTPTimeout(t *testing.T) {
	_, err := konfidant.New(konfidant.ClientOptions{APIKey: "k", HTTPTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestNew_DisabledHTTPTimeout(t *testing.T) {
	_, err := konfidant.New(konfidant.ClientOptions{APIKey: "k", HTTPTimeout: -1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ShareText
// ---------------------------------------------------------------------------

func TestShareText_Success(t *testing.T) {
	expected := konfidant.ShareTextResponse{
		TextID:       "abc",
		ShareURL:     "https://download.konfidant.app?t=tok",
		ExpiresAt:    "2026-06-01 00:00:00",
		VerifiedBurn: true,
	}
	var gotMethod, gotPath, gotAuth string
	var gotBody map[string]any

	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		writeJSON(w, 201, expected)
	})

	result, err := c.ShareText(context.Background(), konfidant.ShareTextRequest{
		Text:     "Secret",
		TTLHours: 24,
	})
	if err != nil {
		t.Fatalf("ShareText: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/api/v1/texts" {
		t.Errorf("path = %q, want /api/v1/texts", gotPath)
	}
	if gotAuth != "Bearer test-key" {
		t.Errorf("auth = %q, want Bearer test-key", gotAuth)
	}
	if gotBody["text"] != "Secret" {
		t.Errorf("body text = %v", gotBody["text"])
	}
	if result.TextID != expected.TextID || result.ShareURL != expected.ShareURL {
		t.Errorf("result = %+v, want %+v", result, expected)
	}
}

func TestShareText_APIError(t *testing.T) {
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 401, map[string]string{"error": "Missing or invalid Authorization header."})
	})

	_, err := c.ShareText(context.Background(), konfidant.ShareTextRequest{Text: "x", TTLHours: 1})
	if err == nil {
		t.Fatal("expected error")
	}
	apiErr, ok := err.(*konfidant.APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != 401 {
		t.Errorf("status = %d, want 401", apiErr.StatusCode)
	}
	if !strings.Contains(apiErr.Error(), "Missing or invalid Authorization header.") {
		t.Errorf("error message missing: %v", apiErr.Error())
	}
}

// ---------------------------------------------------------------------------
// ShareFile
// ---------------------------------------------------------------------------

func TestShareFile_Success(t *testing.T) {
	signed := makeSigned()
	signed.UploadURL = "https://s3.example.com/upload?sig=abc"

	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/files" || r.Method != http.MethodPost {
			http.Error(w, "not found", 404)
			return
		}
		writeJSON(w, 202, signed)
	})

	result, err := c.ShareFile(context.Background(), konfidant.ShareFileRequest{
		Filename: "doc.pdf",
		FileSize: 1024,
		TTLHours: 48,
	})
	if err != nil {
		t.Fatalf("ShareFile: %v", err)
	}
	if result.FileKey != "abc123.zip" {
		t.Errorf("file_key = %q", result.FileKey)
	}
	if result.UploadURL != signed.UploadURL {
		t.Errorf("upload_url = %q", result.UploadURL)
	}
}

func TestShareFile_Unauthorized(t *testing.T) {
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 401, map[string]string{"error": "Unauthorized"})
	})
	_, err := c.ShareFile(context.Background(), konfidant.ShareFileRequest{Filename: "x", FileSize: 1, TTLHours: 1})
	if err == nil {
		t.Fatal("expected error")
	}
	if _, ok := err.(*konfidant.APIError); !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
}

// ---------------------------------------------------------------------------
// GetFileStatus
// ---------------------------------------------------------------------------

func TestGetFileStatus_Processing(t *testing.T) {
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 202, map[string]string{"status": "processing", "message": "Encryption in progress"})
	})

	result, err := c.GetFileStatus(context.Background(), "abc123.zip")
	if err != nil {
		t.Fatalf("GetFileStatus: %v", err)
	}
	if result.Status != "processing" {
		t.Errorf("status = %q, want processing", result.Status)
	}
}

func TestGetFileStatus_Complete(t *testing.T) {
	complete := map[string]any{
		"status":        "complete",
		"file_id":       "file-1",
		"file_name":     "doc.pdf",
		"share_url":     "https://download.konfidant.app?t=tok",
		"expires_at":    "2026-06-01 00:00:00",
		"verified_burn": true,
	}
	var gotPath string
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		writeJSON(w, 200, complete)
	})

	result, err := c.GetFileStatus(context.Background(), "abc123.zip")
	if err != nil {
		t.Fatalf("GetFileStatus: %v", err)
	}
	if gotPath != "/api/v1/files/abc123.zip/status" {
		t.Errorf("path = %q", gotPath)
	}
	if result.Status != "complete" || result.FileID != "file-1" {
		t.Errorf("result = %+v", result)
	}
}

func TestGetFileStatus_URLEncodesFileKey(t *testing.T) {
	var gotPath string
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		writeJSON(w, 200, map[string]any{"status": "complete", "file_id": "x", "file_name": "x", "share_url": "x", "expires_at": "x"})
	})

	_, err := c.GetFileStatus(context.Background(), "has spaces.zip")
	if err != nil {
		t.Fatalf("GetFileStatus: %v", err)
	}
	if !strings.Contains(gotPath, "has%20spaces.zip") {
		t.Errorf("path not URL-encoded: %q", gotPath)
	}
}

func TestGetFileStatus_NotFound(t *testing.T) {
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 404, map[string]string{"error": "File not found"})
	})
	_, err := c.GetFileStatus(context.Background(), "nope")
	if err == nil {
		t.Fatal("expected error")
	}
	if _, ok := err.(*konfidant.APIError); !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
}

// ---------------------------------------------------------------------------
// ListShares
// ---------------------------------------------------------------------------

func TestListShares_NoParams(t *testing.T) {
	body := konfidant.ListSharesResponse{
		Shares:     []konfidant.Share{},
		Pagination: konfidant.Pagination{Total: 0, Limit: 50, Offset: 0, HasMore: false},
	}
	var gotURL string
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.RequestURI()
		writeJSON(w, 200, body)
	})

	_, err := c.ListShares(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListShares: %v", err)
	}
	if gotURL != "/api/v1/shares" {
		t.Errorf("URL = %q, want /api/v1/shares", gotURL)
	}
}

func TestListShares_WithParams(t *testing.T) {
	empty := konfidant.ListSharesResponse{Pagination: konfidant.Pagination{}}
	var gotURL string
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.RequestURI()
		writeJSON(w, 200, empty)
	})

	_, err := c.ListShares(context.Background(), &konfidant.ListSharesParams{
		Type:   "file",
		Status: "active",
		Limit:  10,
		Offset: 20,
	})
	if err != nil {
		t.Fatalf("ListShares: %v", err)
	}
	for _, want := range []string{"type=file", "status=active", "limit=10", "offset=20"} {
		if !strings.Contains(gotURL, want) {
			t.Errorf("URL %q missing %q", gotURL, want)
		}
	}
}

func TestListShares_ReturnsPaginatedShares(t *testing.T) {
	body := konfidant.ListSharesResponse{
		Shares: []konfidant.Share{
			{
				Type:          "file",
				FileName:      "doc.pdf",
				FileSizeBytes: 1024,
				CreatedAt:     "2026-05-01T00:00:00.000Z",
				ExpiresAt:     "2026-05-08T00:00:00.000Z",
				AccessedAt:    nil,
				CreatedBy:     "user@example.com",
			},
		},
		Pagination: konfidant.Pagination{Total: 1, Limit: 50, Offset: 0, HasMore: false},
	}
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, body)
	})

	result, err := c.ListShares(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListShares: %v", err)
	}
	if len(result.Shares) != 1 {
		t.Fatalf("len(shares) = %d, want 1", len(result.Shares))
	}
	if result.Pagination.Total != 1 {
		t.Errorf("pagination.total = %d, want 1", result.Pagination.Total)
	}
}

func TestListShares_Forbidden(t *testing.T) {
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 403, map[string]any{
			"error":            "Insufficient permissions",
			"required_scope":   "shares:list",
			"available_scopes": []string{"files:create"},
		})
	})
	_, err := c.ListShares(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error")
	}
	apiErr, ok := err.(*konfidant.APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != 403 {
		t.Errorf("status = %d, want 403", apiErr.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// UploadFile
// ---------------------------------------------------------------------------

func TestUploadFile_PUTWithCorrectHeaders(t *testing.T) {
	fileContent := []byte("hello")
	var gotMethod string
	var gotHeaders http.Header
	var gotBody []byte

	s3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotHeaders = r.Header.Clone()
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer s3.Close()

	signed := makeSigned()
	signed.UploadURL = s3.URL + "/upload"

	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {}) // unused

	err := c.UploadFile(context.Background(), konfidant.UploadFileOptions{
		Reader:      bytes.NewReader(fileContent),
		Size:        int64(len(fileContent)),
		ContentType: "text/plain",
		Presigned:   signed,
	})
	if err != nil {
		t.Fatalf("UploadFile: %v", err)
	}

	if gotMethod != http.MethodPut {
		t.Errorf("method = %q, want PUT", gotMethod)
	}
	if gotHeaders.Get("Content-Type") != "text/plain" {
		t.Errorf("Content-Type = %q", gotHeaders.Get("Content-Type"))
	}
	if gotHeaders.Get("x-amz-meta-organization-id") != "org-1" {
		t.Errorf("x-amz-meta-organization-id = %q", gotHeaders.Get("x-amz-meta-organization-id"))
	}
	if gotHeaders.Get("x-amz-meta-ttl-hours") != "48" {
		t.Errorf("x-amz-meta-ttl-hours = %q", gotHeaders.Get("x-amz-meta-ttl-hours"))
	}
	if gotHeaders.Get("x-amz-meta-user-id") != "user-1" {
		t.Errorf("x-amz-meta-user-id = %q", gotHeaders.Get("x-amz-meta-user-id"))
	}
	if string(gotBody) != "hello" {
		t.Errorf("body = %q, want hello", string(gotBody))
	}
}

func TestUploadFile_NoAuthHeaderToS3(t *testing.T) {
	var gotAuth string
	s3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer s3.Close()

	signed := makeSigned()
	signed.UploadURL = s3.URL + "/upload"

	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {})

	_ = c.UploadFile(context.Background(), konfidant.UploadFileOptions{
		Reader:      bytes.NewReader([]byte("x")),
		Size:        1,
		ContentType: "text/plain",
		Presigned:   signed,
	})

	if gotAuth != "" {
		t.Errorf("Authorization header should not be sent to S3, got %q", gotAuth)
	}
}

func TestUploadFile_S3Error(t *testing.T) {
	s3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		_, _ = w.Write([]byte("AccessDenied"))
	}))
	defer s3.Close()

	signed := makeSigned()
	signed.UploadURL = s3.URL + "/upload"

	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {})

	err := c.UploadFile(context.Background(), konfidant.UploadFileOptions{
		Reader:      bytes.NewReader([]byte("x")),
		Size:        1,
		ContentType: "text/plain",
		Presigned:   signed,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if _, ok := err.(*konfidant.APIError); !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
}

// ---------------------------------------------------------------------------
// ShareAndUploadFile
// ---------------------------------------------------------------------------

func TestShareAndUploadFile_Success(t *testing.T) {
	processing := map[string]string{"status": "processing", "message": "Encryption in progress"}
	complete := map[string]any{
		"status":        "complete",
		"file_id":       "file-1",
		"file_name":     "doc.pdf",
		"share_url":     "https://download.konfidant.app?t=tok",
		"expires_at":    "2026-06-01 00:00:00",
		"verified_burn": true,
	}

	// S3 upload server
	s3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer s3.Close()

	statusCallCount := 0
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/files":
			signed := makeSigned()
			signed.UploadURL = s3.URL + "/upload"
			writeJSON(w, 202, signed)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/status"):
			statusCallCount++
			if statusCallCount == 1 {
				writeJSON(w, 202, processing)
			} else {
				writeJSON(w, 200, complete)
			}
		default:
			http.Error(w, "unexpected", 500)
		}
	})

	result, err := c.ShareAndUploadFile(
		context.Background(),
		bytes.NewReader([]byte("data")),
		4,
		"doc.pdf",
		"application/pdf",
		48,
		10*time.Millisecond,
		5*time.Second,
	)
	if err != nil {
		t.Fatalf("ShareAndUploadFile: %v", err)
	}
	if result.ShareURL != "https://download.konfidant.app?t=tok" {
		t.Errorf("share_url = %q", result.ShareURL)
	}
	if result.FileID != "file-1" {
		t.Errorf("file_id = %q", result.FileID)
	}
	if statusCallCount != 2 {
		t.Errorf("GetFileStatus called %d times, want 2", statusCallCount)
	}
}

func TestShareAndUploadFile_Timeout(t *testing.T) {
	s3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer s3.Close()

	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/files":
			signed := makeSigned()
			signed.UploadURL = s3.URL + "/upload"
			writeJSON(w, 202, signed)
		default:
			writeJSON(w, 202, map[string]string{"status": "processing", "message": "Encryption in progress"})
		}
	})

	_, err := c.ShareAndUploadFile(
		context.Background(),
		bytes.NewReader([]byte("data")),
		4,
		"doc.pdf",
		"application/pdf",
		48,
		10*time.Millisecond,
		50*time.Millisecond,
	)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("error = %q, want timed out", err.Error())
	}
}

func TestShareAndUploadFile_ContextCancelled(t *testing.T) {
	s3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer s3.Close()

	// API server: files endpoint returns presigned URL; status always returns processing.
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/files" {
			signed := makeSigned()
			signed.UploadURL = s3.URL + "/upload"
			writeJSON(w, 202, signed)
			return
		}
		writeJSON(w, 202, map[string]string{"status": "processing", "message": "Encryption in progress"})
	})

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after the first status poll has been dispatched.
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	_, err := c.ShareAndUploadFile(
		ctx,
		bytes.NewReader([]byte("data")),
		4,
		"doc.pdf",
		"application/pdf",
		48,
		20*time.Millisecond,
		5*time.Second,
	)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("error = %q, want context canceled", err.Error())
	}
}

// ---------------------------------------------------------------------------
// APIError
// ---------------------------------------------------------------------------

func TestAPIError_Fields(t *testing.T) {
	_, c := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 401, map[string]string{"error": "Unauthorized"})
	})

	_, err := c.ShareText(context.Background(), konfidant.ShareTextRequest{Text: "x", TTLHours: 1})
	apiErr, ok := err.(*konfidant.APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != 401 {
		t.Errorf("StatusCode = %d, want 401", apiErr.StatusCode)
	}
	if len(apiErr.Body) == 0 {
		t.Error("Body should not be empty")
	}
	if apiErr.Error() == "" {
		t.Error("Error() should not be empty")
	}
}
