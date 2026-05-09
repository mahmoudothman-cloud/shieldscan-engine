package service

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHTTPError_Error_NoBody(t *testing.T) {
	e := &HTTPError{StatusCode: 404}
	assert.Equal(t, "http error: status 404", e.Error())
}

func TestHTTPError_Error_WithBody(t *testing.T) {
	e := &HTTPError{StatusCode: 500, Body: []byte("internal failure")}
	assert.Contains(t, e.Error(), "500")
	assert.Contains(t, e.Error(), "internal failure")
}

func TestHTTPError_Error_TruncatesLongBody(t *testing.T) {
	body := strings.Repeat("x", 500)
	e := &HTTPError{StatusCode: 500, Body: []byte(body)}
	msg := e.Error()
	assert.Contains(t, msg, "...", "long body must be truncated with ellipsis")
	assert.Less(t, len(msg), 300, "error message must not include full long body")
}

func TestCategorizeHTTPStatus_5xxRetryable(t *testing.T) {
	for _, code := range []int{500, 502, 503, 504, 599} {
		assert.True(t, categorizeHTTPStatus(code), "5xx should be retryable: %d", code)
	}
}

func TestCategorizeHTTPStatus_429Retryable(t *testing.T) {
	assert.True(t, categorizeHTTPStatus(429), "429 rate limit must be retryable")
}

func TestCategorizeHTTPStatus_4xxElseNotRetryable(t *testing.T) {
	for _, code := range []int{400, 401, 403, 404, 422} {
		assert.False(t, categorizeHTTPStatus(code), "4xx (except 429) must not be retryable: %d", code)
	}
}

func TestCategorizeHTTPStatus_2xx3xxNotRetryable(t *testing.T) {
	for _, code := range []int{200, 201, 204, 301, 302} {
		assert.False(t, categorizeHTTPStatus(code), "2xx/3xx must not be retryable: %d", code)
	}
}
