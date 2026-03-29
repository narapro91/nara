package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// ── Mock S3 client ──────────────────────────────────────────────────────────

type mockS3 struct {
	output *s3.GetObjectOutput
	err    error
}

func (m *mockS3) GetObject(_ context.Context, _ *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return m.output, m.err
}

// ── Helper: build a test App ─────────────────────────────────────────────────

func newTestApp(mock *mockS3, token, prefix string) *App {
	return &App{
		s3:            mock,
		bucketName:    "test-bucket",
		verifyToken:   token,
		allowedPrefix: prefix,
	}
}

// ── Helper: build a Lambda Function URL request ──────────────────────────────

func makeReq(key, token string) events.LambdaFunctionURLRequest {
	req := events.LambdaFunctionURLRequest{
		QueryStringParameters: map[string]string{},
		Headers:               map[string]string{},
	}
	if key != "" {
		req.QueryStringParameters["key"] = key
	}
	if token != "" {
		// Lambda Function URL always lowercases headers.
		req.Headers["x-origin-verify"] = token
	}
	return req
}

// ── Helper: decode base64 body from a response ────────────────────────────────

func decodeBody(t *testing.T, resp events.LambdaFunctionURLResponse) []byte {
	t.Helper()
	if !resp.IsBase64Encoded {
		return []byte(resp.Body)
	}
	b, err := base64.StdEncoding.DecodeString(resp.Body)
	if err != nil {
		t.Fatalf("base64 decode error: %v", err)
	}
	return b
}

// ── validateKey tests ─────────────────────────────────────────────────────────

func TestValidateKey(t *testing.T) {
	tests := []struct {
		name          string
		key           string
		allowedPrefix string
		wantErr       bool
		errContains   string
	}{
		{
			name:    "empty key is rejected",
			key:     "",
			wantErr: true, errContains: "must not be empty",
		},
		{
			name:    "simple key is accepted",
			key:     "images/photo.jpg",
			wantErr: false,
		},
		{
			name:    "path traversal with .. is rejected",
			key:     "../secret",
			wantErr: true, errContains: "invalid path components",
		},
		{
			name:    "embedded path traversal is rejected",
			key:     "images/../../etc/passwd",
			wantErr: true, errContains: "invalid path components",
		},
		{
			name:    "absolute path is rejected",
			key:     "/etc/passwd",
			wantErr: true, errContains: "relative path",
		},
		{
			name:          "key matches allowed prefix",
			key:           "public/photo.jpg",
			allowedPrefix: "public/",
			wantErr:       false,
		},
		{
			name:          "key outside allowed prefix is rejected",
			key:           "private/secret.txt",
			allowedPrefix: "public/",
			wantErr:       true, errContains: "outside the allowed prefix",
		},
		{
			name:    "nested path without traversal is accepted",
			key:     "a/b/c/file.txt",
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateKey(tc.key, tc.allowedPrefix)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error but got nil")
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("expected error to contain %q, got %q", tc.errContains, err.Error())
				}
				t.Logf("  ✓  error: %v", err)
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				t.Logf("  ✓  key %q accepted", tc.key)
			}
		})
	}
}

// ── jsonError tests ───────────────────────────────────────────────────────────

func TestJsonError(t *testing.T) {
	cases := []struct {
		code    int
		message string
	}{
		{http.StatusBadRequest, "missing key"},
		{http.StatusForbidden, "forbidden"},
		{http.StatusNotFound, "not found"},
		{http.StatusInternalServerError, "internal error"},
	}
	for _, c := range cases {
		resp := jsonError(c.code, c.message)
		if resp.StatusCode != c.code {
			t.Errorf("jsonError(%d, %q): want status %d, got %d", c.code, c.message, c.code, resp.StatusCode)
		}
		if ct := resp.Headers["Content-Type"]; ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %q", ct)
		}
		// Body must be valid JSON with an "error" field.
		var body map[string]string
		if err := json.Unmarshal([]byte(resp.Body), &body); err != nil {
			t.Errorf("body is not valid JSON: %v — body: %s", err, resp.Body)
		}
		if body["error"] != c.message {
			t.Errorf("want error field %q, got %q", c.message, body["error"])
		}
		t.Logf("  ✓  HTTP %d → %s", c.code, resp.Body)
	}
}

// ── handler tests ─────────────────────────────────────────────────────────────

func TestHandler_ForbiddenWhenTokenMissing(t *testing.T) {
	app := newTestApp(&mockS3{}, "supersecret", "")
	req := makeReq("images/photo.jpg", "") // no token header

	resp, err := app.handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d — body: %s", resp.StatusCode, resp.Body)
	}
	t.Logf("  ✓  missing token → 403 Forbidden: %s", resp.Body)
}

func TestHandler_ForbiddenWhenTokenWrong(t *testing.T) {
	app := newTestApp(&mockS3{}, "supersecret", "")
	req := makeReq("images/photo.jpg", "wrongtoken")

	resp, err := app.handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
	t.Logf("  ✓  wrong token → 403 Forbidden: %s", resp.Body)
}

func TestHandler_NoTokenCheckWhenTokenDisabled(t *testing.T) {
	// When verifyToken is empty the check is disabled entirely.
	content := []byte("hello world")
	app := newTestApp(&mockS3{
		output: &s3.GetObjectOutput{
			Body:        io.NopCloser(bytes.NewReader(content)),
			ContentType: aws.String("text/plain"),
		},
	}, "" /* no token */, "")

	req := makeReq("docs/readme.txt", "") // no token header – should still work

	resp, err := app.handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d — body: %s", resp.StatusCode, resp.Body)
	}
	t.Logf("  ✓  token check disabled → 200 OK")
}

func TestHandler_BadRequestWhenKeyEmpty(t *testing.T) {
	app := newTestApp(&mockS3{}, "", "")
	req := makeReq("", "")

	resp, err := app.handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
	t.Logf("  ✓  empty key → 400 Bad Request: %s", resp.Body)
}

func TestHandler_BadRequestOnPathTraversal(t *testing.T) {
	app := newTestApp(&mockS3{}, "", "")
	req := makeReq("../../etc/passwd", "")

	resp, err := app.handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
	t.Logf("  ✓  path traversal → 400 Bad Request: %s", resp.Body)
}

func TestHandler_BadRequestWhenKeyOutsidePrefix(t *testing.T) {
	app := newTestApp(&mockS3{}, "", "public/")
	req := makeReq("private/secret.txt", "")

	resp, err := app.handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
	t.Logf("  ✓  key outside prefix → 400 Bad Request: %s", resp.Body)
}

func TestHandler_NotFoundWhenS3Errors(t *testing.T) {
	app := newTestApp(&mockS3{err: fmt.Errorf("NoSuchKey")}, "", "")
	req := makeReq("missing/file.txt", "")

	resp, err := app.handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404, got %d", resp.StatusCode)
	}
	t.Logf("  ✓  S3 error → 404 Not Found: %s", resp.Body)
}

func TestHandler_TooLargeFromContentLength(t *testing.T) {
	bigLen := int64(maxObjectBytes + 1)
	app := newTestApp(&mockS3{
		output: &s3.GetObjectOutput{
			Body:          io.NopCloser(strings.NewReader("")),
			ContentLength: &bigLen,
		},
	}, "", "")
	req := makeReq("big/file.bin", "")

	resp, err := app.handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413, got %d", resp.StatusCode)
	}
	t.Logf("  ✓  Content-Length too large → 413 Request Entity Too Large: %s", resp.Body)
}

func TestHandler_TooLargeFromBodyWithoutContentLength(t *testing.T) {
	// Simulate an object that is exactly 1 byte over the limit but has no
	// Content-Length header – the limit is enforced by io.LimitReader.
	overLimit := bytes.Repeat([]byte("x"), maxObjectBytes+1)
	app := newTestApp(&mockS3{
		output: &s3.GetObjectOutput{
			Body: io.NopCloser(bytes.NewReader(overLimit)),
			// ContentLength intentionally nil
		},
	}, "", "")
	req := makeReq("big/file.bin", "")

	resp, err := app.handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413, got %d", resp.StatusCode)
	}
	t.Logf("  ✓  body without Content-Length too large → 413 Request Entity Too Large: %s", resp.Body)
}

func TestHandler_SuccessTextFile(t *testing.T) {
	content := []byte("Hello, CloudFront!")
	etag := `"abc123"`
	app := newTestApp(&mockS3{
		output: &s3.GetObjectOutput{
			Body:        io.NopCloser(bytes.NewReader(content)),
			ContentType: aws.String("text/plain; charset=utf-8"),
			ETag:        aws.String(etag),
		},
	}, "", "")
	req := makeReq("docs/hello.txt", "")

	resp, err := app.handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d — body: %s", resp.StatusCode, resp.Body)
	}
	if !resp.IsBase64Encoded {
		t.Fatal("expected IsBase64Encoded=true")
	}
	got := decodeBody(t, resp)
	if !bytes.Equal(got, content) {
		t.Fatalf("body mismatch: want %q, got %q", content, got)
	}
	if ct := resp.Headers["Content-Type"]; ct != "text/plain; charset=utf-8" {
		t.Errorf("want Content-Type text/plain; charset=utf-8, got %q", ct)
	}
	if resp.Headers["ETag"] != etag {
		t.Errorf("want ETag %q, got %q", etag, resp.Headers["ETag"])
	}
	if _, hasLen := resp.Headers["Content-Length"]; hasLen {
		t.Error("Content-Length must NOT be set in the response (base64 inflates body size)")
	}
	t.Logf("  ✓  200 OK — Content-Type: %s, ETag: %s, body: %q",
		resp.Headers["Content-Type"], resp.Headers["ETag"], got)
}

func TestHandler_SuccessBinaryFile(t *testing.T) {
	// Simulate a small PNG header (binary content).
	content := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	app := newTestApp(&mockS3{
		output: &s3.GetObjectOutput{
			Body:        io.NopCloser(bytes.NewReader(content)),
			ContentType: aws.String("image/png"),
		},
	}, "", "")
	req := makeReq("images/logo.png", "")

	resp, err := app.handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d — body: %s", resp.StatusCode, resp.Body)
	}
	got := decodeBody(t, resp)
	if !bytes.Equal(got, content) {
		t.Fatalf("binary body mismatch: want %x, got %x", content, got)
	}
	t.Logf("  ✓  200 OK — binary PNG prefix correctly base64-encoded and decoded")
}

func TestHandler_SuccessWithTokenVerification(t *testing.T) {
	token := "my-very-secret-token-32chars!!!!"
	content := []byte("secured content")
	app := newTestApp(&mockS3{
		output: &s3.GetObjectOutput{
			Body:        io.NopCloser(bytes.NewReader(content)),
			ContentType: aws.String("text/plain"),
		},
	}, token, "")
	req := makeReq("secure/file.txt", token)

	resp, err := app.handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d — body: %s", resp.StatusCode, resp.Body)
	}
	got := decodeBody(t, resp)
	if string(got) != string(content) {
		t.Fatalf("body mismatch: want %q, got %q", content, got)
	}
	t.Logf("  ✓  200 OK with correct token — body: %q", got)
}

func TestHandler_SuccessWithDefaultContentType(t *testing.T) {
	// When S3 ContentType is nil the handler defaults to application/octet-stream.
	content := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	app := newTestApp(&mockS3{
		output: &s3.GetObjectOutput{
			Body: io.NopCloser(bytes.NewReader(content)),
			// ContentType intentionally nil
		},
	}, "", "")
	req := makeReq("data/blob.bin", "")

	resp, err := app.handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	if ct := resp.Headers["Content-Type"]; ct != "application/octet-stream" {
		t.Errorf("want application/octet-stream, got %q", ct)
	}
	t.Logf("  ✓  nil ContentType → default application/octet-stream")
}

func TestHandler_CacheControlHeaderPresent(t *testing.T) {
	content := []byte("cached asset")
	app := newTestApp(&mockS3{
		output: &s3.GetObjectOutput{
			Body:        io.NopCloser(bytes.NewReader(content)),
			ContentType: aws.String("text/css"),
		},
	}, "", "")
	req := makeReq("styles/main.css", "")

	resp, err := app.handler(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cc := resp.Headers["Cache-Control"]; cc != "public, max-age=3600" {
		t.Errorf("want Cache-Control public, max-age=3600, got %q", cc)
	}
	t.Logf("  ✓  Cache-Control: %s", resp.Headers["Cache-Control"])
}
