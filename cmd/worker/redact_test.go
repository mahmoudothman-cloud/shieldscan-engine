package main

import (
	"strings"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testRedisSecret = "b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184"

func TestRedactRedisCredential(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "empty username with leading colon (our URL shape)",
			in:   "redis://:" + testRedisSecret + "@localhost:6379/0",
			want: "redis://:***@localhost:6379/0",
		},
		{
			name: "username and password",
			in:   "redis://default:" + testRedisSecret + "@localhost:6379/0",
			want: "redis://default:***@localhost:6379/0",
		},
		{
			name: "rediss scheme",
			in:   "rediss://:" + testRedisSecret + "@redis.example.com:6380/1",
			want: "rediss://:***@redis.example.com:6380/1",
		},
		{
			name: "quoted inside a url.Parse-style error",
			in:   `parse "redis://:` + testRedisSecret + `@localhost:banana": invalid port`,
			want: `parse "redis://:***@localhost:banana": invalid port`,
		},
		{
			name: "no credential is left untouched",
			in:   "redis://localhost:6379/0",
			want: "redis://localhost:6379/0",
		},
		{
			name: "unrelated text is left untouched",
			in:   "redis: invalid URL scheme: http",
			want: "redis: invalid URL scheme: http",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := redactRedisCredential(tc.in)
			assert.Equal(t, tc.want, got)
			assert.NotContains(t, got, testRedisSecret)
		})
	}
}

// TestRedactRedisCredential_CoversRealParseURLError pins the actual defect:
// go-redis returns a url.Parse error that quotes the URL verbatim, so logging
// err.Error() unredacted would write the password to stdout and the log file.
func TestRedactRedisCredential_CoversRealParseURLError(t *testing.T) {
	malformed := "redis://:" + testRedisSecret + "@localhost:not-a-port/0"
	_, err := redis.ParseURL(malformed)
	require.Error(t, err)
	require.Contains(t, err.Error(), testRedisSecret,
		"precondition: the raw ParseURL error leaks the password")

	redacted := redactRedisCredential(err.Error())
	assert.NotContains(t, redacted, testRedisSecret)
	assert.True(t, strings.Contains(redacted, "***"), "expected a redaction marker")
}
