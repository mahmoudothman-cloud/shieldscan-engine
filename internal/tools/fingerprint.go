package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/odyssey/shieldscan-engine/internal/events"
)

// ComputeFingerprint returns a deterministic SHA-256 fingerprint for
// a finding, used by the M9 AI pipeline as the primary-pass dedup key
// (per ../shieldscan-docs/CLAUDE.md gotcha 4).
//
// Algorithm (TOOL-ARCHITECTURE.md §3.4):
//
//	SHA-256(tool_name | finding_type | target_url | parameter | code_file | code_line)
//
// Components are pipe-separated. The pipe choice is deliberate: it
// avoids ambiguity between adjacent fields that may legitimately
// contain other separators (slashes in URLs, colons in code locations,
// commas in parameters). If a finding's TargetURL contains a literal
// pipe character — technically allowed in URLs but rare in practice —
// fingerprint collisions become possible across pathological inputs.
// If/when collisions surface in production, the algorithm gets
// versioned and migrated; do NOT change the algorithm in place
// without a migration plan because existing data depends on it.
//
// Cross-language parity: any future Python computation of the same
// fingerprint MUST use the byte-equivalent algorithm (same component
// order, same separator, same hash function, same hex encoding).
//
// Exported (vs the plan literal's lowercase computeFingerprint) so
// the M5.5 processor and future M9 AI pipeline consume the canonical
// algorithm without duplication. See engine DRIFT-LOG 2026-05-01
// "ComputeFingerprint exported" entry.
func ComputeFingerprint(f events.RawFinding) string {
	components := []string{
		f.ToolName,
		f.FindingType,
		f.TargetURL,
		f.Parameter,
		f.CodeFile,
		strconv.Itoa(f.CodeLine),
	}
	h := sha256.Sum256([]byte(strings.Join(components, "|")))
	return hex.EncodeToString(h[:])
}
