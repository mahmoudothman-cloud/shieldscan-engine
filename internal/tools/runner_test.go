package tools

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTarget_AuthConfig_JSON_Roundtrip pins Task 7.3 Q6 lock —
// AuthConfig wire-payload JSON tags deserialize correctly per SPEC §7.1.
// AuthConfig field lives on Target (pre-existing engine placement;
// Task 7.3 D1 deviation reframe — design doc Q6 referenced ScanConfig).
func TestTarget_AuthConfig_JSON_Roundtrip(t *testing.T) {
	t.Run("cookie type", func(t *testing.T) {
		raw := `{"url":"https://example.com","auth_config":{"type":"cookie","data":"session=abc123"}}`
		var tgt Target
		require.NoError(t, json.Unmarshal([]byte(raw), &tgt))
		require.NotNil(t, tgt.AuthConfig)
		assert.Equal(t, "cookie", tgt.AuthConfig.Type)
		assert.Equal(t, "session=abc123", tgt.AuthConfig.Data)
		assert.Nil(t, tgt.AuthConfig.Fields)
	})

	t.Run("form type with fields", func(t *testing.T) {
		raw := `{"url":"https://example.com","auth_config":{"type":"form","data":"","fields":{"username":"alice","password":"secret"}}}`
		var tgt Target
		require.NoError(t, json.Unmarshal([]byte(raw), &tgt))
		require.NotNil(t, tgt.AuthConfig)
		assert.Equal(t, "form", tgt.AuthConfig.Type)
		assert.Equal(t, "alice", tgt.AuthConfig.Fields["username"])
	})

	t.Run("absent → nil", func(t *testing.T) {
		raw := `{"url":"https://example.com"}`
		var tgt Target
		require.NoError(t, json.Unmarshal([]byte(raw), &tgt))
		assert.Nil(t, tgt.AuthConfig)
	})

	t.Run("omitempty marshals out when nil", func(t *testing.T) {
		tgt := Target{URL: "https://example.com"}
		out, err := json.Marshal(tgt)
		require.NoError(t, err)
		assert.NotContains(t, string(out), "auth_config")
	})
}
