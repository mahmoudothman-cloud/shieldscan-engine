package zap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateTarget_Cases(t *testing.T) {
	cases := []struct {
		name         string
		url          string
		allowPrivate bool
		wantErr      bool
		errSubstr    string
	}{
		{"empty URL", "", false, true, "URL required"},
		{"missing scheme", "example.com", false, true, "scheme must be"},
		{"unsupported scheme", "ftp://example.com", false, true, "scheme must be"},
		{"happy https", "https://example.com/path", false, false, ""},
		{"happy http with port", "http://example.com:8080/", false, false, ""},
		{"hostname (DNS) accepted", "http://internal.local", false, false, ""},
		{"RFC1918 10.x rejected", "http://10.0.0.1/", false, true, "RFC1918"},
		{"RFC1918 192.168 rejected", "http://192.168.1.1:8080/", false, true, "RFC1918"},
		{"loopback rejected", "http://127.0.0.1/", false, true, "RFC1918"},
		{"link-local rejected", "http://169.254.1.1/", false, true, "RFC1918"},
		{"RFC1918 accepted with allowPrivate", "http://10.0.0.1/", true, false, ""},
		{"loopback accepted with allowPrivate", "http://127.0.0.1/", true, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTarget(tc.url, tc.allowPrivate)
			if tc.wantErr {
				require.Error(t, err)
				if tc.errSubstr != "" {
					assert.Contains(t, err.Error(), tc.errSubstr)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestExtractHostPort(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want string
	}{
		{"https default 443", "https://example.com/", "example.com:443"},
		{"http default 80", "http://example.com/", "example.com:80"},
		{"explicit port preserved", "http://example.com:8080/api", "example.com:8080"},
		{"hostname lowercased", "https://EXAMPLE.COM/", "example.com:443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractHostPort(tc.url)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
