package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const maxObjectBytes = 50 * 1024 * 1024 // 50 MB safety limit

var (
	s3Client          *s3.Client
	bucketName        string
	originVerifyToken string
	allowedPrefix     string // optional prefix restriction, e.g. "assets/"
)

func init() {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatalf("unable to load AWS SDK config: %v", err)
	}

	s3Client = s3.NewFromConfig(cfg)

	bucketName = os.Getenv("BUCKET_NAME")
	if bucketName == "" {
		log.Fatal("BUCKET_NAME environment variable is required")
	}

	// Optional shared-secret to verify requests arrive via CloudFront.
	originVerifyToken = os.Getenv("ORIGIN_VERIFY_TOKEN")

	// Optional prefix restriction (e.g. "public/"). Empty means no restriction.
	allowedPrefix = os.Getenv("ALLOWED_PREFIX")
}

func jsonError(statusCode int, message string) events.LambdaFunctionURLResponse {
	return events.LambdaFunctionURLResponse{
		StatusCode: statusCode,
		Body:       fmt.Sprintf(`{"error":%q}`, message),
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}
}

// validateKey rejects path-traversal attempts and enforces an optional prefix.
func validateKey(key string) error {
	if key == "" {
		return fmt.Errorf("key must not be empty")
	}

	// Resolve any ".." components and ensure the cleaned path does not escape.
	// path.Clean operates on slash-separated paths (suitable for S3 keys).
	cleaned := path.Clean(key)
	if strings.HasPrefix(cleaned, "..") || strings.Contains(cleaned, "/../") {
		return fmt.Errorf("key contains invalid path components")
	}

	// Reject absolute paths (keys must be relative).
	if strings.HasPrefix(cleaned, "/") {
		return fmt.Errorf("key must be a relative path")
	}

	// Enforce allowed prefix when configured.
	if allowedPrefix != "" && !strings.HasPrefix(cleaned, allowedPrefix) {
		return fmt.Errorf("key is outside the allowed prefix")
	}

	return nil
}

func handler(ctx context.Context, req events.LambdaFunctionURLRequest) (events.LambdaFunctionURLResponse, error) {
	// Lambda Function URL normalises all incoming headers to lowercase.
	// Verify the shared-secret header so that direct Function URL calls are
	// rejected; only CloudFront (which injects the header) can reach the origin.
	if originVerifyToken != "" {
		if req.Headers["x-origin-verify"] != originVerifyToken {
			log.Printf("forbidden: missing or invalid x-origin-verify header")
			return jsonError(http.StatusForbidden, "forbidden"), nil
		}
	}

	key := req.QueryStringParameters["key"]
	if err := validateKey(key); err != nil {
		log.Printf("invalid key %q: %v", key, err)
		return jsonError(http.StatusBadRequest, err.Error()), nil
	}

	log.Printf("fetching s3 object: bucket=%s key=%s", bucketName, key)

	result, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(key),
	})
	if err != nil {
		log.Printf("s3 GetObject error for key %q: %v", key, err)
		return jsonError(http.StatusNotFound, fmt.Sprintf("object not found: %s", key)), nil
	}
	defer result.Body.Close()

	// Reject objects that exceed the safety limit before reading them into memory.
	if result.ContentLength != nil && *result.ContentLength > maxObjectBytes {
		log.Printf("object too large: key=%s size=%d limit=%d", key, *result.ContentLength, maxObjectBytes)
		return jsonError(http.StatusRequestEntityTooLarge, "object exceeds maximum allowed size"), nil
	}

	// Read up to maxObjectBytes + 1 so we detect objects that are exactly at
	// the limit but whose Content-Length was not set by the S3 metadata.
	body, err := io.ReadAll(io.LimitReader(result.Body, maxObjectBytes+1))
	if err != nil {
		log.Printf("error reading s3 body for key %q: %v", key, err)
		return jsonError(http.StatusInternalServerError, "failed to read object body"), nil
	}
	if int64(len(body)) > maxObjectBytes {
		log.Printf("object too large (no Content-Length): key=%s", key)
		return jsonError(http.StatusRequestEntityTooLarge, "object exceeds maximum allowed size"), nil
	}

	contentType := "application/octet-stream"
	if result.ContentType != nil && *result.ContentType != "" {
		contentType = *result.ContentType
	}

	headers := map[string]string{
		"Content-Type":  contentType,
		"Cache-Control": "public, max-age=3600",
	}

	// Omit Content-Length: the body is base64-encoded, which increases its size
	// by ~33%, so the original S3 ContentLength value would be incorrect here.
	// CloudFront / the client will use chunked transfer or content framing.

	if result.ETag != nil {
		headers["ETag"] = *result.ETag
	}

	return events.LambdaFunctionURLResponse{
		StatusCode:      http.StatusOK,
		Body:            base64.StdEncoding.EncodeToString(body),
		IsBase64Encoded: true,
		Headers:         headers,
	}, nil
}

func main() {
	lambda.Start(handler)
}
