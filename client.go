// Package konfidant is the official Go SDK for the Konfidant API.
//
// Content is encrypted on your machine (KNF1, AES-256-GCM) before anything is sent. The key is placed only in the
// share link's URL fragment, which browsers never send to a server, so Konfidant stores and delivers ciphertext it
// cannot read.
package konfidant

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Version is the SDK version.
const Version = "1.1.0"

const (
	defaultBaseURL     = "https://www.konfidant.app"
	defaultHTTPTimeout = 120 * time.Second
	userAgent          = "konfidant-go/" + Version
	maxErrorBodyBytes  = 64 << 10
)

var errUploadAborted = errors.New("konfidant: upload aborted")

// Client is the Konfidant API client.
type Client struct {
	apiKey  string
	baseURL string
	http    *http.Client
}

// New creates a new Client. Returns an error if APIKey is empty.
func New(opts ClientOptions) (*Client, error) {
	if opts.APIKey == "" {
		return nil, fmt.Errorf("konfidant: APIKey is required")
	}
	base := defaultBaseURL
	if opts.BaseURL != "" {
		base = strings.TrimRight(opts.BaseURL, "/")
	}
	timeout := defaultHTTPTimeout
	if opts.HTTPTimeout < 0 {
		timeout = 0 // disabled
	} else if opts.HTTPTimeout > 0 {
		timeout = opts.HTTPTimeout
	}
	return &Client{
		apiKey:  opts.APIKey,
		baseURL: base,
		http:    &http.Client{Timeout: timeout},
	}, nil
}

// readAPIError builds an *APIError from a non-2xx response.
func readAPIError(resp *http.Response, summary string) *APIError {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
	apiErr := &APIError{StatusCode: resp.StatusCode, Body: body, summary: summary}
	var parsed struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &parsed) == nil {
		apiErr.Code = parsed.Error
		apiErr.Message = parsed.Message
	}
	return apiErr
}

// doJSON sends an authenticated request to the Konfidant API and decodes a JSON response into out.
func (c *Client) doJSON(ctx context.Context, method, path string, payload, out any) error {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return readAPIError(resp, "HTTP "+strconv.Itoa(resp.StatusCode))
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("konfidant: decoding %s %s response: %w", method, path, err)
	}
	return nil
}

// buildShareURL appends the key to the fragment of a server-issued download URL ("https://<host>/#t=<token>").
// It refuses URLs without a "#t=" fragment, which would otherwise put the key where a server could see it.
func buildShareURL(downloadURL string, key []byte) (string, error) {
	_, fragment, found := strings.Cut(downloadURL, "#")
	if !found || !strings.HasPrefix(fragment, "t=") || len(fragment) == len("t=") {
		return "", fmt.Errorf("konfidant: unexpected download_url from server (no #t= fragment)")
	}
	return downloadURL + "&k=" + EncodeKey(key), nil
}

// ShareText encrypts text locally and creates a one-time text share. Only ciphertext is sent to Konfidant.
func (c *Client) ShareText(ctx context.Context, text string, opts ShareOptions) (*ShareResult, error) {
	key := GenerateKey()
	var ciphertext bytes.Buffer
	if _, err := Encrypt(&ciphertext, key, Metadata{Kind: KindText}, strings.NewReader(text), int64(len(text))); err != nil {
		return nil, err
	}
	payload := struct {
		Ciphertext string `json:"ciphertext"`
		TTLHours   int    `json:"ttl_hours,omitempty"`
	}{base64.StdEncoding.EncodeToString(ciphertext.Bytes()), opts.TTLHours}

	var resp struct {
		DownloadURL string    `json:"download_url"`
		TextID      string    `json:"text_id"`
		ExpiresAt   time.Time `json:"expires_at"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/texts", payload, &resp); err != nil {
		return nil, err
	}
	shareURL, err := buildShareURL(resp.DownloadURL, key)
	if err != nil {
		return nil, err
	}
	return &ShareResult{ShareURL: shareURL, ID: resp.TextID, ExpiresAt: resp.ExpiresAt}, nil
}

// ShareFile encrypts size bytes from r locally and shares them as a one-time file: it creates an upload, streams
// the ciphertext to the upload URL while encrypting (the file is never held in memory as a whole) and completes
// the upload. The file name and content type are encrypted together with the content. r must yield exactly size
// bytes.
func (c *Client) ShareFile(ctx context.Context, r io.Reader, size int64, opts FileShareOptions) (*FileShareResult, error) {
	meta := Metadata{Kind: KindFile, Name: opts.Filename, MIME: opts.ContentType}
	ciphertextSize, err := CiphertextSize(meta, size)
	if err != nil {
		return nil, err
	}
	key := GenerateKey()

	upload, err := c.CreateFileUpload(ctx, ciphertextSize, opts.TTLHours)
	if err != nil {
		return nil, err
	}

	pr, pw := io.Pipe()
	encErr := make(chan error, 1)
	go func() {
		_, err := Encrypt(pw, key, meta, r, size)
		_ = pw.CloseWithError(err)
		encErr <- err
	}()
	uploadErr := c.UploadCiphertext(ctx, upload, pr)
	_ = pr.CloseWithError(errUploadAborted) // unblocks the encryptor if the upload stopped reading early
	if err := <-encErr; err != nil && !errors.Is(err, errUploadAborted) {
		return nil, err
	}
	if uploadErr != nil {
		return nil, uploadErr
	}

	done, err := c.CompleteFileUpload(ctx, upload.FileKey)
	if err != nil {
		return nil, err
	}
	shareURL, err := buildShareURL(done.DownloadURL, key)
	if err != nil {
		return nil, err
	}
	return &FileShareResult{
		ShareURL:     shareURL,
		FileID:       done.FileID,
		ExpiresAt:    done.ExpiresAt,
		VerifiedBurn: done.VerifiedBurn,
	}, nil
}

// CreateFileUpload reserves a file share for ciphertextSize bytes of KNF1 ciphertext (see CiphertextSize) and
// returns a short-lived upload URL. Low-level: ShareFile does this for you.
func (c *Client) CreateFileUpload(ctx context.Context, ciphertextSize int64, ttlHours int) (*FileUpload, error) {
	if ciphertextSize <= 0 {
		return nil, fmt.Errorf("konfidant: ciphertext size must be positive")
	}
	payload := struct {
		CiphertextSize int64 `json:"ciphertext_size"`
		TTLHours       int   `json:"ttl_hours,omitempty"`
	}{ciphertextSize, ttlHours}
	var upload FileUpload
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/files", payload, &upload); err != nil {
		return nil, err
	}
	if upload.UploadURL == "" || upload.FileKey == "" {
		return nil, fmt.Errorf("konfidant: incomplete upload response from server")
	}
	upload.CiphertextSize = ciphertextSize
	return &upload, nil
}

// UploadCiphertext PUTs exactly upload.CiphertextSize bytes of KNF1 ciphertext from r to upload.UploadURL with
// the server-provided upload headers. The Konfidant Authorization header is never sent to the upload URL.
// Low-level: ShareFile does this for you.
func (c *Client) UploadCiphertext(ctx context.Context, upload *FileUpload, r io.Reader) error {
	if upload == nil || upload.UploadURL == "" {
		return fmt.Errorf("konfidant: upload URL is required")
	}
	if upload.CiphertextSize <= 0 {
		return fmt.Errorf("konfidant: upload.CiphertextSize must be positive")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, upload.UploadURL, io.NopCloser(r))
	if err != nil {
		return err
	}
	req.ContentLength = upload.CiphertextSize
	for name, value := range upload.UploadHeaders {
		if strings.EqualFold(name, "Content-Length") {
			continue // set via req.ContentLength
		}
		req.Header.Set(name, value)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return readAPIError(resp, "ciphertext upload failed")
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBodyBytes))
	return nil
}

// CompleteFileUpload finalizes an uploaded file share and returns its download URL (without the key). It returns
// an error matching ErrUploadIncomplete if the ciphertext has not been fully uploaded. Low-level: ShareFile does
// this for you.
func (c *Client) CompleteFileUpload(ctx context.Context, fileKey string) (*CompletedUpload, error) {
	if fileKey == "" {
		return nil, fmt.Errorf("konfidant: fileKey is required")
	}
	var done CompletedUpload
	path := "/api/v1/files/" + url.PathEscape(fileKey) + "/complete"
	if err := c.doJSON(ctx, http.MethodPost, path, nil, &done); err != nil {
		return nil, err
	}
	return &done, nil
}

// ListShares lists all shares for the authenticated organization.
// Pass nil for params to use defaults.
func (c *Client) ListShares(ctx context.Context, params *ListSharesParams) (*ListSharesResponse, error) {
	qs := url.Values{}
	if params != nil {
		if params.Type != "" {
			qs.Set("type", params.Type)
		}
		if params.Status != "" {
			qs.Set("status", params.Status)
		}
		if params.Limit > 0 {
			qs.Set("limit", strconv.Itoa(params.Limit))
		}
		if params.Offset > 0 {
			qs.Set("offset", strconv.Itoa(params.Offset))
		}
	}
	path := "/api/v1/shares"
	if len(qs) > 0 {
		path += "?" + qs.Encode()
	}
	var resp ListSharesResponse
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// OpenShare fetches and decrypts a share link ("https://<host>/#t=<token>&k=<key>") as its recipient would. This
// consumes the share: it can be opened only once. The API key is not sent. An error matching ErrShareUnavailable
// means the share was already opened or has expired.
func (c *Client) OpenShare(ctx context.Context, shareURL string) (*OpenedShare, error) {
	return openShare(ctx, c.http, shareURL)
}

// OpenShare is like Client.OpenShare but needs no API key; it uses an HTTP client with the default timeout.
func OpenShare(ctx context.Context, shareURL string) (*OpenedShare, error) {
	return openShare(ctx, &http.Client{Timeout: defaultHTTPTimeout}, shareURL)
}

func openShare(ctx context.Context, hc *http.Client, shareURL string) (*OpenedShare, error) {
	u, err := url.Parse(shareURL)
	if err != nil {
		return nil, fmt.Errorf("konfidant: invalid share URL: %w", err)
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("konfidant: invalid share URL: must be an http(s) URL")
	}
	fragment, err := url.ParseQuery(u.EscapedFragment())
	if err != nil {
		return nil, fmt.Errorf("konfidant: invalid share URL fragment: %w", err)
	}
	token, encodedKey := fragment.Get("t"), fragment.Get("k")
	if token == "" || encodedKey == "" {
		return nil, fmt.Errorf("konfidant: invalid share URL: fragment must contain t= and k=")
	}
	key, err := DecodeKey(encodedKey)
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(map[string]string{"t": token})
	if err != nil {
		return nil, err
	}
	endpoint := (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/api/download"}).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("User-Agent", userAgent)

	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, readAPIError(resp, "HTTP "+strconv.Itoa(resp.StatusCode))
	}
	return decryptFrom(key, resp.Body)
}
