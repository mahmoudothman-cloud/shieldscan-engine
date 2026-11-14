package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// State is what `enroll` writes and `run` reads: the API base URL and
// the agent key. File mode 0600; the key is never logged or printed.
type State struct {
	APIBase        string `json:"api_base"`
	AgentID        string `json:"agent_id"`
	OrganizationID string `json:"organization_id"`
	Name           string `json:"name"`
	AgentKey       string `json:"agent_key"`
}

// ErrNotEnrolled is returned by LoadState when no state file exists.
var ErrNotEnrolled = errors.New("agent is not enrolled (run `shieldscan-agent enroll --token …` first)")

// DefaultStateDir is where the state file lives unless
// SHIELDSCAN_AGENT_STATE_DIR says otherwise: /var/lib/shieldscan-agent
// when writable (the systemd unit's StateDirectory), else
// ~/.shieldscan-agent.
func DefaultStateDir() string {
	if d := os.Getenv("SHIELDSCAN_AGENT_STATE_DIR"); d != "" {
		return d
	}
	if runtime.GOOS == "linux" {
		if st, err := os.Stat("/var/lib/shieldscan-agent"); err == nil && st.IsDir() {
			if f, err := os.CreateTemp("/var/lib/shieldscan-agent", ".w"); err == nil {
				_ = f.Close()
				_ = os.Remove(f.Name())
				return "/var/lib/shieldscan-agent"
			}
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".shieldscan-agent"
	}
	return filepath.Join(home, ".shieldscan-agent")
}

func statePath(dir string) string { return filepath.Join(dir, "agent.json") }

// SaveState writes the state file atomically with mode 0600.
func SaveState(dir string, st State) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("state dir: %w", err)
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := statePath(dir) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	if err := os.Rename(tmp, statePath(dir)); err != nil {
		return fmt.Errorf("commit state: %w", err)
	}
	return nil
}

// LoadState reads the state file; ErrNotEnrolled when absent.
func LoadState(dir string) (*State, error) {
	data, err := os.ReadFile(statePath(dir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotEnrolled
		}
		return nil, fmt.Errorf("read state: %w", err)
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("state file %s is not valid JSON: %w", statePath(dir), err)
	}
	if st.AgentKey == "" || st.APIBase == "" {
		return nil, fmt.Errorf("state file %s is incomplete", statePath(dir))
	}
	return &st, nil
}

// RemoveState deletes the state file (after a revoke, so the next run
// says "not enrolled" instead of retrying a dead key).
func RemoveState(dir string) error {
	err := os.Remove(statePath(dir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
