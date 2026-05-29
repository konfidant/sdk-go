package konfidant

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultBaseURL     = "https://www.konfidant.app"
	defaultHTTPTimeout = 120 * time.Second
)

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
	if opts.HTTPTimeout != 0 {
		if opts.HTTPTimeout < 0 {
			timeout = 0 // disabled
		} else {
			timeout = opts.HTTPTimeout
		}
	}
	return &Client{
		apiKey:  opts.APIKey,
		baseURL: base,
		http:    &http.Client{Timeout: timeout},
	}, nil
}

func (c *Client) authHeaders() map[string]string {
	return map[string]string{
		"Authorization": "Bearer " + c.apiKey,
		"Content-Type":  "application/json",
	}
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader, extraHeaders map[string]string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, 0, err
	}
	for k, v := range c.authHeaders() {
		req.Header.Set(k, v)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := fmt.Sprintf("HTTP %d", resp.StatusCode)
		var errBody struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(respBody, &errBody) == nil && errBody.Error != "" {
			msg = errBody.Error
		}
		return nil, resp.StatusCode, newAPIError(msg, resp.StatusCode, respBody)
	}

	return respBody, resp.StatusCode, nil
}

func (c *Client) postJSON(ctx context.Context, path string, payload any, out any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	respBody, _, err := c.do(ctx, http.MethodPost, path, bytes.NewReader(b), nil)
	if err != nil {
		return err
	}
	return json.Unmarshal(respBody, out)
}

func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	respBody, _, err := c.do(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return err
	}
	return json.Unmarshal(respBody, out)
}

// ShareText encrypts and shares a text message.
func (c *Client) ShareText(ctx context.Context, req ShareTextRequest) (*ShareTextResponse, error) {
	var resp ShareTextResponse
	if err := c.postJSON(ctx, "/api/v1/texts", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ShareFile requests a presigned upload URL. Use the returned response with
// UploadFile to complete the upload, then poll GetFileStatus for the share link.
func (c *Client) ShareFile(ctx context.Context, req ShareFileRequest) (*ShareFileResponse, error) {
	var resp ShareFileResponse
	if err := c.postJSON(ctx, "/api/v1/files", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetFileStatus polls the encryption status of an uploaded file.
func (c *Client) GetFileStatus(ctx context.Context, fileKey string) (*FileStatusResponse, error) {
	path := "/api/v1/files/" + url.PathEscape(fileKey) + "/status"
	var resp FileStatusResponse
	if err := c.getJSON(ctx, path, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
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
	if err := c.getJSON(ctx, path, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// UploadFile sends file bytes to the presigned S3 URL from ShareFile.
// It does NOT include the Konfidant Authorization header in the S3 request.
func (c *Client) UploadFile(ctx context.Context, opts UploadFileOptions) error {
	p := opts.Presigned
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, p.UploadURL, opts.Reader)
	if err != nil {
		return err
	}
	req.ContentLength = opts.Size
	req.Header.Set("Content-Type", opts.ContentType)
	req.Header.Set("x-amz-meta-organization-id", p.MetadataHeaders.OrganizationID)
	req.Header.Set("x-amz-meta-ttl-hours", p.MetadataHeaders.TTLHours)
	req.Header.Set("x-amz-meta-user-id", p.MetadataHeaders.UserID)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return newAPIError(fmt.Sprintf("file upload failed: HTTP %d", resp.StatusCode), resp.StatusCode, body)
	}
	return nil
}

// ShareAndUploadFile is a convenience wrapper that calls ShareFile, UploadFile,
// then polls GetFileStatus until complete. pollInterval defaults to 2s; timeout
// defaults to 60s when zero.
func (c *Client) ShareAndUploadFile(
	ctx context.Context,
	r io.Reader,
	size int64,
	filename, contentType string,
	ttlHours int,
	pollInterval, timeout time.Duration,
) (*ShareResult, error) {
	if pollInterval <= 0 {
		pollInterval = 2 * time.Second
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}

	presigned, err := c.ShareFile(ctx, ShareFileRequest{
		Filename: filename,
		FileSize: size,
		TTLHours: ttlHours,
	})
	if err != nil {
		return nil, err
	}

	if err := c.UploadFile(ctx, UploadFileOptions{
		Reader:      r,
		Size:        size,
		ContentType: contentType,
		Presigned:   *presigned,
	}); err != nil {
		return nil, err
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		status, err := c.GetFileStatus(ctx, presigned.FileKey)
		if err != nil {
			return nil, err
		}
		if status.Status == "complete" {
			return &ShareResult{
				ShareURL:     status.ShareURL,
				FileID:       status.FileID,
				ExpiresAt:    status.ExpiresAt,
				VerifiedBurn: status.VerifiedBurn,
			}, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pollInterval):
		}
	}

	return nil, fmt.Errorf("konfidant: encryption timed out after %s", timeout)
}
