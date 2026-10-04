package konfidant_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	konfidant "github.com/konfidant/sdk-go"
)

// ---------------------------------------------------------------------------
// Fake Konfidant server
// ---------------------------------------------------------------------------

// fakeServer implements the v1 API, the upload storage and the recipient download endpoint in memory.
type fakeServer struct {
	t   *testing.T
	srv *httptest.Server

	mu            sync.Mutex
	stored        map[string][]byte // token -> ciphertext
	uploads       map[string][]byte // file key -> uploaded ciphertext
	declaredSize  map[string]int64  // file key -> ciphertext_size
	requests      []string
	textTTL       int
	textIDNull    bool
	completeCalls int

	// Hooks to override behavior per test.
	uploadStatus   int
	completeStatus int
	downloadURL    func(token string) string
}

const testAPIKey = "test-key"
const testToken = "tok+/=&special"

var testExpiry = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

func newFakeServer(t *testing.T) (*fakeServer, *konfidant.Client) {
	t.Helper()
	f := &fakeServer{
		t:            t,
		stored:       map[string][]byte{},
		uploads:      map[string][]byte{},
		declaredSize: map[string]int64{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	f.downloadURL = func(token string) string {
		return f.srv.URL + "/#t=" + url.QueryEscape(token)
	}
	c, err := konfidant.New(konfidant.ClientOptions{APIKey: testAPIKey, BaseURL: f.srv.URL + "/"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return f, c
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (f *fakeServer) log(r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
}

func (f *fakeServer) requireAPIAuth(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("Authorization") != "Bearer "+testAPIKey {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Missing or invalid Authorization header."})
		return false
	}
	return true
}

func (f *fakeServer) handle(w http.ResponseWriter, r *http.Request) {
	f.log(r)
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/texts":
		f.handleText(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/files":
		f.handleCreateFile(w, r)
	case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/upload/"):
		f.handleUpload(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v1/files/") && strings.HasSuffix(r.URL.Path, "/complete"):
		f.handleComplete(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/download":
		f.handleDownload(w, r)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
	}
}

func (f *fakeServer) handleText(w http.ResponseWriter, r *http.Request) {
	if !f.requireAPIAuth(w, r) {
		return
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	for field := range body {
		if field != "ciphertext" && field != "ttl_hours" {
			f.t.Errorf("unexpected field %q in text request", field)
		}
	}
	encoded, _ := body["ciphertext"].(string)
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || !bytes.HasPrefix(ciphertext, []byte("KNF1")) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_ciphertext"})
		return
	}
	ttl, _ := body["ttl_hours"].(float64)
	f.mu.Lock()
	f.textTTL = int(ttl)
	f.stored[testToken] = ciphertext
	f.mu.Unlock()
	var textID any = "text-123"
	if f.textIDNull {
		textID = nil
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"download_url": f.downloadURL(testToken),
		"text_id":      textID,
		"expires_at":   testExpiry.Format(time.RFC3339),
	})
}

func (f *fakeServer) handleCreateFile(w http.ResponseWriter, r *http.Request) {
	if !f.requireAPIAuth(w, r) {
		return
	}
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	for field := range body {
		if field != "ciphertext_size" && field != "ttl_hours" {
			f.t.Errorf("unexpected field %q in file request", field)
		}
	}
	size, _ := body["ciphertext_size"].(float64)
	if size <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_size"})
		return
	}
	const fileKey = "org-1/abc123"
	f.mu.Lock()
	f.declaredSize[fileKey] = int64(size)
	f.mu.Unlock()
	writeJSON(w, http.StatusCreated, map[string]any{
		"upload_url": f.srv.URL + "/upload/abc123?X-Amz-Signature=sig",
		"file_key":   fileKey,
		"upload_headers": map[string]string{
			"Content-Type":      "application/octet-stream",
			"x-amz-meta-ttl":    "48",
			"x-amz-meta-org-id": "org-1",
		},
		"upload_expires_in": 900,
	})
}

func (f *fakeServer) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "" {
		f.t.Errorf("upload request must not carry an Authorization header")
	}
	if r.Header.Get("Content-Type") != "application/octet-stream" || r.Header.Get("x-amz-meta-ttl") != "48" ||
		r.Header.Get("x-amz-meta-org-id") != "org-1" {
		f.t.Errorf("upload headers not forwarded: %v", r.Header)
	}
	if r.URL.Query().Get("X-Amz-Signature") != "sig" {
		f.t.Errorf("upload URL query lost: %s", r.URL)
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return // client aborted
	}
	f.mu.Lock()
	declared := f.declaredSize["org-1/abc123"]
	f.mu.Unlock()
	if r.ContentLength != declared || int64(len(body)) != declared {
		f.t.Errorf("upload ContentLength=%d body=%d, declared ciphertext_size=%d", r.ContentLength, len(body), declared)
	}
	if f.uploadStatus != 0 {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(f.uploadStatus)
		_, _ = io.WriteString(w, "<Error><Code>SignatureDoesNotMatch</Code></Error>")
		return
	}
	f.mu.Lock()
	f.uploads["org-1/abc123"] = body
	f.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (f *fakeServer) handleComplete(w http.ResponseWriter, r *http.Request) {
	if !f.requireAPIAuth(w, r) {
		return
	}
	f.mu.Lock()
	f.completeCalls++
	f.mu.Unlock()
	if r.ContentLength > 0 {
		f.t.Errorf("complete request must have no body")
	}
	fileKey := strings.TrimSuffix(strings.TrimPrefix(r.URL.EscapedPath(), "/api/v1/files/"), "/complete")
	if fileKey != "org-1%2Fabc123" {
		f.t.Errorf("file key not path-escaped: %q", fileKey)
	}
	if f.completeStatus == http.StatusConflict {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "upload_incomplete"})
		return
	}
	f.mu.Lock()
	body, ok := f.uploads["org-1/abc123"]
	if ok {
		f.stored[testToken] = body
	}
	f.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "upload_incomplete"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"download_url":  f.downloadURL(testToken),
		"file_id":       "file-456",
		"expires_at":    testExpiry.Format(time.RFC3339),
		"verified_burn": true,
	})
}

func (f *fakeServer) handleDownload(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "" {
		f.t.Errorf("download request must not carry an Authorization header")
	}
	if r.Header.Get("Content-Type") != "application/json" {
		f.t.Errorf("download Content-Type = %q", r.Header.Get("Content-Type"))
	}
	var body struct {
		T string `json:"t"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	f.mu.Lock()
	ciphertext, ok := f.stored[body.T]
	delete(f.stored, body.T) // single use
	f.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusGone, map[string]string{"error": "gone", "message": "This link has already been used or has expired."})
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(ciphertext)
}

func (f *fakeServer) requestLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

// keyFromShareURL checks the share URL shape and returns the decoded key.
func keyFromShareURL(t *testing.T, f *fakeServer, shareURL string) []byte {
	t.Helper()
	prefix := f.srv.URL + "/#t=" + url.QueryEscape(testToken) + "&k="
	if !strings.HasPrefix(shareURL, prefix) {
		t.Fatalf("share URL %q does not start with %q", shareURL, prefix)
	}
	encoded := strings.TrimPrefix(shareURL, prefix)
	key, err := konfidant.DecodeKey(encoded)
	if err != nil {
		t.Fatalf("key in share URL: %v", err)
	}
	u, _ := url.Parse(shareURL)
	if u.RawQuery != "" || strings.Contains(u.Path, encoded) {
		t.Fatal("key must only appear in the URL fragment")
	}
	return key
}

// ---------------------------------------------------------------------------
// New
// ---------------------------------------------------------------------------

func TestNew_MissingAPIKey(t *testing.T) {
	_, err := konfidant.New(konfidant.ClientOptions{})
	if err == nil || !strings.Contains(err.Error(), "APIKey is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNew_Options(t *testing.T) {
	for _, opts := range []konfidant.ClientOptions{
		{APIKey: "k"},
		{APIKey: "k", BaseURL: "https://example.com/"},
		{APIKey: "k", HTTPTimeout: 5 * time.Second},
		{APIKey: "k", HTTPTimeout: -1},
	} {
		if _, err := konfidant.New(opts); err != nil {
			t.Fatalf("New(%+v): %v", opts, err)
		}
	}
	if konfidant.Version != "1.1.0" {
		t.Fatalf("Version = %q", konfidant.Version)
	}
}

func TestClient_UserAgent(t *testing.T) {
	var ua string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.Header.Get("User-Agent")
		writeJSON(w, http.StatusOK, map[string]any{"shares": []any{}, "pagination": map[string]any{}})
	}))
	defer srv.Close()
	c, _ := konfidant.New(konfidant.ClientOptions{APIKey: "k", BaseURL: srv.URL})
	if _, err := c.ListShares(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if ua != "konfidant-go/"+konfidant.Version {
		t.Fatalf("User-Agent = %q", ua)
	}
}

// ---------------------------------------------------------------------------
// ShareText
// ---------------------------------------------------------------------------

func TestShareText(t *testing.T) {
	f, c := newFakeServer(t)
	res, err := c.ShareText(context.Background(), "super-secret-password 🔐", konfidant.ShareOptions{TTLHours: 24})
	if err != nil {
		t.Fatalf("ShareText: %v", err)
	}
	if res.ID != "text-123" || !res.ExpiresAt.Equal(testExpiry) || f.textTTL != 24 {
		t.Fatalf("result = %+v, ttl sent = %d", res, f.textTTL)
	}
	key := keyFromShareURL(t, f, res.ShareURL)

	f.mu.Lock()
	ciphertext := f.stored[testToken]
	f.mu.Unlock()
	if bytes.Contains(ciphertext, []byte("super-secret")) {
		t.Fatal("plaintext leaked to the server")
	}
	opened, err := konfidant.Decrypt(key, ciphertext)
	if err != nil || opened.Kind != konfidant.KindText || string(opened.Data) != "super-secret-password 🔐" {
		t.Fatalf("server ciphertext does not decrypt with the link key: %v", err)
	}
}

func TestShareText_NullIDAndDefaultTTL(t *testing.T) {
	f, c := newFakeServer(t)
	f.textIDNull = true
	res, err := c.ShareText(context.Background(), "x", konfidant.ShareOptions{})
	if err != nil {
		t.Fatalf("ShareText: %v", err)
	}
	if res.ID != "" || f.textTTL != 0 {
		t.Fatalf("ID = %q, ttl = %d", res.ID, f.textTTL)
	}
}

func TestShareText_FreshKeyPerShare(t *testing.T) {
	_, c := newFakeServer(t)
	a, err1 := c.ShareText(context.Background(), "x", konfidant.ShareOptions{})
	b, err2 := c.ShareText(context.Background(), "x", konfidant.ShareOptions{})
	if err1 != nil || err2 != nil || a.ShareURL == b.ShareURL {
		t.Fatalf("each share must use a fresh key: %v %v", err1, err2)
	}
}

func TestShareText_APIError(t *testing.T) {
	f, _ := newFakeServer(t)
	c, _ := konfidant.New(konfidant.ClientOptions{APIKey: "wrong", BaseURL: f.srv.URL})
	_, err := c.ShareText(context.Background(), "x", konfidant.ShareOptions{})
	var apiErr *konfidant.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %v", err)
	}
	if apiErr.StatusCode != 401 || apiErr.Code != "unauthorized" || apiErr.Message != "Missing or invalid Authorization header." {
		t.Fatalf("APIError = %+v", apiErr)
	}
	if !strings.Contains(apiErr.Error(), "unauthorized: Missing or invalid Authorization header. (HTTP 401)") {
		t.Fatalf("Error() = %q", apiErr.Error())
	}
}

func TestShareText_RejectsDownloadURLWithoutFragment(t *testing.T) {
	f, c := newFakeServer(t)
	for _, bad := range []string{"https://download.konfidant.app/", "https://download.konfidant.app/?t=abc", "https://download.konfidant.app/#t="} {
		f.downloadURL = func(string) string { return bad }
		if _, err := c.ShareText(context.Background(), "x", konfidant.ShareOptions{}); err == nil || !strings.Contains(err.Error(), "download_url") {
			t.Fatalf("download_url %q: err = %v", bad, err)
		}
	}
}

func TestShareText_NonJSONError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}))
	defer srv.Close()
	c, _ := konfidant.New(konfidant.ClientOptions{APIKey: "k", BaseURL: srv.URL})
	_, err := c.ShareText(context.Background(), "x", konfidant.ShareOptions{})
	var apiErr *konfidant.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 502 || apiErr.Code != "" || apiErr.Error() != "konfidant: HTTP 502 (HTTP 502)" {
		t.Fatalf("err = %v", err)
	}
}

// ---------------------------------------------------------------------------
// ShareFile and the low-level upload steps
// ---------------------------------------------------------------------------

func TestShareFile_MultiChunk(t *testing.T) {
	f, c := newFakeServer(t)
	content := randomBytes(t, 2*konfidant.DefaultChunkSize+999)
	res, err := c.ShareFile(context.Background(), bytes.NewReader(content), int64(len(content)), konfidant.FileShareOptions{
		Filename: "Quarterly report – Q3.pdf", ContentType: "application/pdf", TTLHours: 48,
	})
	if err != nil {
		t.Fatalf("ShareFile: %v", err)
	}
	if res.FileID != "file-456" || !res.VerifiedBurn || !res.ExpiresAt.Equal(testExpiry) {
		t.Fatalf("result = %+v", res)
	}
	key := keyFromShareURL(t, f, res.ShareURL)

	want := []string{"POST /api/v1/files", "PUT /upload/abc123", "POST /api/v1/files/org-1/abc123/complete"}
	if got := f.requestLog(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("requests = %v, want %v", got, want)
	}
	f.mu.Lock()
	uploaded := f.uploads["org-1/abc123"]
	f.mu.Unlock()
	if bytes.Contains(uploaded, []byte("Quarterly")) {
		t.Fatal("file name leaked to the server")
	}
	opened, err := konfidant.Decrypt(key, uploaded)
	if err != nil {
		t.Fatalf("decrypt upload: %v", err)
	}
	if opened.Kind != konfidant.KindFile || opened.Name != "Quarterly report – Q3.pdf" || opened.MIME != "application/pdf" || !bytes.Equal(opened.Data, content) {
		t.Fatal("uploaded ciphertext does not round-trip")
	}
}

func TestShareFile_EmptyFile(t *testing.T) {
	f, c := newFakeServer(t)
	res, err := c.ShareFile(context.Background(), bytes.NewReader(nil), 0, konfidant.FileShareOptions{Filename: "empty.txt"})
	if err != nil {
		t.Fatalf("ShareFile: %v", err)
	}
	opened, err := c.OpenShare(context.Background(), res.ShareURL)
	if err != nil || opened.Name != "empty.txt" || len(opened.Data) != 0 {
		t.Fatalf("OpenShare: %+v, %v", opened, err)
	}
	_ = f
}

func TestShareFile_InvalidMetadataSendsNothing(t *testing.T) {
	f, c := newFakeServer(t)
	_, err := c.ShareFile(context.Background(), strings.NewReader("x"), 1, konfidant.FileShareOptions{
		Filename: strings.Repeat("n", konfidant.MaxNameBytes+1),
	})
	if !errors.Is(err, konfidant.ErrInvalidFormat) {
		t.Fatalf("err = %v", err)
	}
	if len(f.requestLog()) != 0 {
		t.Fatalf("no request expected, got %v", f.requestLog())
	}
}

func TestShareFile_ShortReader(t *testing.T) {
	f, c := newFakeServer(t)
	_, err := c.ShareFile(context.Background(), strings.NewReader("abc"), 10, konfidant.FileShareOptions{Filename: "f"})
	if err == nil || !strings.Contains(err.Error(), "shorter than the declared size") {
		t.Fatalf("err = %v", err)
	}
	if f.completeCalls != 0 {
		t.Fatal("complete must not be called after a failed upload")
	}
}

func TestShareFile_UploadFails(t *testing.T) {
	f, c := newFakeServer(t)
	f.uploadStatus = http.StatusForbidden
	content := randomBytes(t, 100000)
	_, err := c.ShareFile(context.Background(), bytes.NewReader(content), int64(len(content)), konfidant.FileShareOptions{Filename: "f"})
	var apiErr *konfidant.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 403 || !strings.Contains(string(apiErr.Body), "SignatureDoesNotMatch") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(apiErr.Error(), "ciphertext upload failed (HTTP 403)") {
		t.Fatalf("Error() = %q", apiErr.Error())
	}
	if f.completeCalls != 0 {
		t.Fatal("complete must not be called after a failed upload")
	}
}

func TestShareFile_UploadIncomplete(t *testing.T) {
	f, c := newFakeServer(t)
	f.completeStatus = http.StatusConflict
	_, err := c.ShareFile(context.Background(), strings.NewReader("data"), 4, konfidant.FileShareOptions{Filename: "f"})
	if !errors.Is(err, konfidant.ErrUploadIncomplete) {
		t.Fatalf("err = %v, want ErrUploadIncomplete", err)
	}
	if errors.Is(err, konfidant.ErrShareUnavailable) {
		t.Fatal("409 must not match ErrShareUnavailable")
	}
}

func TestLowLevelFileFlow(t *testing.T) {
	f, c := newFakeServer(t)
	ctx := context.Background()
	key := konfidant.GenerateKey()
	meta := konfidant.Metadata{Kind: konfidant.KindFile, Name: "notes.txt", MIME: "text/plain"}
	content := []byte("low-level")
	size, err := konfidant.CiphertextSize(meta, int64(len(content)))
	if err != nil {
		t.Fatal(err)
	}

	upload, err := c.CreateFileUpload(ctx, size, 1)
	if err != nil {
		t.Fatalf("CreateFileUpload: %v", err)
	}
	if upload.FileKey != "org-1/abc123" || upload.UploadExpiresIn != 900 || upload.CiphertextSize != size ||
		upload.UploadHeaders["Content-Type"] != "application/octet-stream" {
		t.Fatalf("upload = %+v", upload)
	}

	// Completing before uploading returns 409.
	if _, err := c.CompleteFileUpload(ctx, upload.FileKey); !errors.Is(err, konfidant.ErrUploadIncomplete) {
		t.Fatalf("early complete: err = %v", err)
	}

	var ciphertext bytes.Buffer
	if _, err := konfidant.Encrypt(&ciphertext, key, meta, bytes.NewReader(content), int64(len(content))); err != nil {
		t.Fatal(err)
	}
	if err := c.UploadCiphertext(ctx, upload, &ciphertext); err != nil {
		t.Fatalf("UploadCiphertext: %v", err)
	}
	done, err := c.CompleteFileUpload(ctx, upload.FileKey)
	if err != nil {
		t.Fatalf("CompleteFileUpload: %v", err)
	}
	if done.FileID != "file-456" || !done.VerifiedBurn || !strings.Contains(done.DownloadURL, "#t=") {
		t.Fatalf("done = %+v", done)
	}

	opened, err := c.OpenShare(ctx, done.DownloadURL+"&k="+konfidant.EncodeKey(key))
	if err != nil || string(opened.Data) != "low-level" || opened.Name != "notes.txt" {
		t.Fatalf("OpenShare: %+v, %v", opened, err)
	}
	_ = f
}

func TestLowLevel_Validation(t *testing.T) {
	_, c := newFakeServer(t)
	ctx := context.Background()
	if _, err := c.CreateFileUpload(ctx, 0, 1); err == nil {
		t.Fatal("CreateFileUpload(0) must fail")
	}
	if err := c.UploadCiphertext(ctx, nil, strings.NewReader("")); err == nil {
		t.Fatal("UploadCiphertext(nil) must fail")
	}
	if err := c.UploadCiphertext(ctx, &konfidant.FileUpload{UploadURL: "http://x"}, strings.NewReader("")); err == nil {
		t.Fatal("UploadCiphertext without size must fail")
	}
	if _, err := c.CompleteFileUpload(ctx, ""); err == nil {
		t.Fatal("CompleteFileUpload(\"\") must fail")
	}
}

func TestCreateFileUpload_IncompleteResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusCreated, map[string]any{"file_key": "k"})
	}))
	defer srv.Close()
	c, _ := konfidant.New(konfidant.ClientOptions{APIKey: "k", BaseURL: srv.URL})
	if _, err := c.CreateFileUpload(context.Background(), 100, 1); err == nil {
		t.Fatal("expected error for missing upload_url")
	}
}

// ---------------------------------------------------------------------------
// ListShares
// ---------------------------------------------------------------------------

func TestListShares(t *testing.T) {
	var gotQuery url.Values
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/shares" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		gotQuery, gotAuth = r.URL.Query(), r.Header.Get("Authorization")
		writeJSON(w, http.StatusOK, map[string]any{
			"shares": []map[string]any{
				{"type": "file", "file_size_bytes": 2048, "created_at": "2026-10-01T10:00:00Z", "expires_at": "2026-10-02T10:00:00Z", "accessed_at": nil, "created_by": "a@example.com"},
				{"type": "text", "file_size_bytes": 0, "created_at": "2026-10-01T11:00:00Z", "expires_at": "2026-10-02T11:00:00Z", "accessed_at": "2026-10-01T12:00:00Z", "created_by": "b@example.com"},
			},
			"pagination": map[string]any{"total": 2, "limit": 10, "offset": 5, "has_more": false},
		})
	}))
	defer srv.Close()
	c, _ := konfidant.New(konfidant.ClientOptions{APIKey: "k", BaseURL: srv.URL})

	resp, err := c.ListShares(context.Background(), &konfidant.ListSharesParams{Type: "file", Status: "active", Limit: 10, Offset: 5})
	if err != nil {
		t.Fatalf("ListShares: %v", err)
	}
	if gotAuth != "Bearer k" || gotQuery.Get("type") != "file" || gotQuery.Get("status") != "active" ||
		gotQuery.Get("limit") != "10" || gotQuery.Get("offset") != "5" {
		t.Fatalf("auth=%q query=%v", gotAuth, gotQuery)
	}
	if len(resp.Shares) != 2 || resp.Shares[0].FileSizeBytes != 2048 || resp.Shares[0].AccessedAt != nil ||
		resp.Shares[1].AccessedAt == nil || resp.Shares[1].CreatedBy != "b@example.com" || resp.Pagination.Total != 2 {
		t.Fatalf("resp = %+v", resp)
	}

	if _, err := c.ListShares(context.Background(), nil); err != nil || len(gotQuery) != 0 {
		t.Fatalf("nil params: err=%v query=%v", err, gotQuery)
	}
}

func TestListShares_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "insufficient_scope"})
	}))
	defer srv.Close()
	c, _ := konfidant.New(konfidant.ClientOptions{APIKey: "k", BaseURL: srv.URL})
	_, err := c.ListShares(context.Background(), nil)
	var apiErr *konfidant.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 403 || apiErr.Code != "insufficient_scope" {
		t.Fatalf("err = %v", err)
	}
}

func TestListShares_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "not json")
	}))
	defer srv.Close()
	c, _ := konfidant.New(konfidant.ClientOptions{APIKey: "k", BaseURL: srv.URL})
	if _, err := c.ListShares(context.Background(), nil); err == nil {
		t.Fatal("expected decode error")
	}
}

// ---------------------------------------------------------------------------
// OpenShare
// ---------------------------------------------------------------------------

func TestOpenShare_TextEndToEnd(t *testing.T) {
	_, c := newFakeServer(t)
	ctx := context.Background()
	res, err := c.ShareText(ctx, "open me", konfidant.ShareOptions{TTLHours: 1})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := c.OpenShare(ctx, res.ShareURL)
	if err != nil {
		t.Fatalf("OpenShare: %v", err)
	}
	if opened.Kind != konfidant.KindText || string(opened.Data) != "open me" || opened.Name != "" {
		t.Fatalf("opened = %+v", opened)
	}

	// Single use: the second open gets 410.
	_, err = c.OpenShare(ctx, res.ShareURL)
	if !errors.Is(err, konfidant.ErrShareUnavailable) {
		t.Fatalf("second open: err = %v, want ErrShareUnavailable", err)
	}
	var apiErr *konfidant.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 410 || apiErr.Code != "gone" {
		t.Fatalf("APIError = %+v", apiErr)
	}
}

func TestOpenShare_PackageLevelWithoutAPIKey(t *testing.T) {
	_, c := newFakeServer(t)
	res, err := c.ShareFile(context.Background(), strings.NewReader("file body"), 9, konfidant.FileShareOptions{Filename: "a.txt", ContentType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := konfidant.OpenShare(context.Background(), res.ShareURL)
	if err != nil || opened.Kind != konfidant.KindFile || opened.MIME != "text/plain" || string(opened.Data) != "file body" {
		t.Fatalf("OpenShare: %+v, %v", opened, err)
	}
}

func TestOpenShare_WrongKey(t *testing.T) {
	f, c := newFakeServer(t)
	if _, err := c.ShareText(context.Background(), "secret", konfidant.ShareOptions{}); err != nil {
		t.Fatal(err)
	}
	wrong := f.downloadURL(testToken) + "&k=" + konfidant.EncodeKey(konfidant.GenerateKey())
	if _, err := c.OpenShare(context.Background(), wrong); !errors.Is(err, konfidant.ErrDecrypt) {
		t.Fatalf("err = %v, want ErrDecrypt", err)
	}
}

func TestOpenShare_TamperedCiphertext(t *testing.T) {
	f, c := newFakeServer(t)
	res, err := c.ShareText(context.Background(), "secret", konfidant.ShareOptions{})
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.stored[testToken][len(f.stored[testToken])-1] ^= 1
	f.mu.Unlock()
	if _, err := c.OpenShare(context.Background(), res.ShareURL); !errors.Is(err, konfidant.ErrDecrypt) {
		t.Fatalf("err = %v, want ErrDecrypt", err)
	}
}

func TestOpenShare_InvalidURLs(t *testing.T) {
	_, c := newFakeServer(t)
	key := konfidant.EncodeKey(konfidant.GenerateKey())
	cases := map[string]string{
		"not a URL":    "::::",
		"ftp scheme":   "ftp://download.konfidant.app/#t=a&k=" + key,
		"no host":      "https:///#t=a&k=" + key,
		"no fragment":  "https://download.konfidant.app/",
		"missing key":  "https://download.konfidant.app/#t=abc",
		"missing t":    "https://download.konfidant.app/#k=" + key,
		"bad key":      "https://download.konfidant.app/#t=abc&k=short",
		"bad encoding": "https://download.konfidant.app/#t=%zz&k=" + key,
	}
	for name, shareURL := range cases {
		if _, err := c.OpenShare(context.Background(), shareURL); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
}
