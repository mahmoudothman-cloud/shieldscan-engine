package depcheck

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/odyssey/shieldscan-engine/internal/tools/jsonx"
	"github.com/rs/zerolog"
)

// parseOutputFile returns a closure satisfying NativeRunner.ParseOutputFile.
//
// File-output mode (ADR-023): Dep-Check writes findings to the
// outputFilePath provided by NativeRunner. Stdout is logging chatter,
// not findings. This closure reads the file, parses the JSON, and
// synthesizes per-CVE RawFindings.
//
// Per-CVE granularity: 1 dep with 5 CVEs → 5 RawFindings. Each
// finding has the same CodeFile (dep file path) but distinct
// FindingType (CVE id). Mirrors industry SCA tooling conventions.
//
// ParseOutputFile leaves these RawFinding fields EMPTY (NativeRunner.Run
// enriches after parsing):
//   - ToolName ("depcheck"), EngineCategory ("sca")
//   - DiscoveredAt (RFC3339)
//   - Fingerprint (via tools.ComputeFingerprint)
//
// File cleanup is NativeRunner's responsibility (deferred os.Remove
// in Run); this closure MUST NOT delete outputFilePath.
func parseOutputFile(log zerolog.Logger) func(string) ([]events.RawFinding, error) {
	return func(outputFilePath string) ([]events.RawFinding, error) {
		findings := []events.RawFinding{}
		data, err := os.ReadFile(outputFilePath) //nolint:gosec // G304: path comes from NativeRunner-minted tempfile, not user input
		if err != nil {
			return nil, fmt.Errorf("depcheck: read output file: %w", err)
		}
		if len(data) == 0 {
			return findings, nil
		}

		var doc map[string]any
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("depcheck: parse JSON: %w", err)
		}

		deps, ok := doc["dependencies"].([]any)
		if !ok {
			// Missing or wrong-type → empty happy path.
			return findings, nil
		}

		for i, depAny := range deps {
			dep, ok := depAny.(map[string]any)
			if !ok {
				log.Warn().Int("dep_index", i).
					Msg("depcheck: dependency entry not an object; dropping")
				continue
			}
			filePath := jsonx.ExtractString(dep, "filePath")
			if filePath == "" {
				log.Warn().Int("dep_index", i).
					Str("fileName", jsonx.ExtractString(dep, "fileName")).
					Msg("depcheck: dependency missing filePath; skipping (and its CVEs)")
				continue
			}
			fileName := jsonx.ExtractString(dep, "fileName")

			vulns, _ := dep["vulnerabilities"].([]any)
			if len(vulns) == 0 {
				continue // clean dep; no findings
			}
			for j, vAny := range vulns {
				v, ok := vAny.(map[string]any)
				if !ok {
					continue
				}
				name := jsonx.ExtractString(v, "name")
				if name == "" {
					log.Warn().
						Int("dep_index", i).Int("vuln_index", j).
						Str("filePath", filePath).
						Msg("depcheck: vulnerability missing 'name' (CVE id); skipping")
					continue
				}
				findings = append(findings, vulnToFinding(name, filePath, fileName, v))
			}
		}
		return findings, nil
	}
}

// vulnToFinding builds a RawFinding from a single Dep-Check
// vulnerability entry. Per-CVE granularity per Watch item C.
//
// Field map (Dep-Check vulnerability → RawFinding):
//
//	name               → FindingType, Title (CVE id)
//	description        → Description (with " (in <fileName>)" fold if fileName non-empty)
//	severity           → Severity (via mapSeverity)
//	cwes[0]            → CWEID (first only, consistent with Nuclei)
//	cvssv3.baseScore   → CVSSScore
//	(dep) filePath     → CodeFile
//
// Reductions (DRIFT-LOG M6.7 entry 10):
//   - references[]            DROP (no field; deeply nested)
//   - vulnerableSoftware[]    DROP (CPE version ranges)
//   - dep.md5/sha1/sha256     DROP (hashes; not actionable)
//   - dep.evidenceCollected   DROP (tool internals)
//   - cwes[1+]                DROP (first-only convention)
func vulnToFinding(name, filePath, fileName string, v map[string]any) events.RawFinding {
	description := jsonx.ExtractString(v, "description")
	if fileName != "" {
		if description == "" {
			description = "in " + fileName
		} else {
			description = description + " (in " + fileName + ")"
		}
	}
	cvssv3 := jsonx.ExtractMap(v, "cvssv3")
	score := jsonx.ExtractFloat(cvssv3, "baseScore")

	// SPEC §7.3 schema extension (M6-close-followup, ADR-024).
	// Dep-Check retrofit per design doc §4.1.4:
	//   - References    ← references[].url (extract URL from each
	//                     reference object)
	//   - CVSSVector    ← composed from cvssv3 word-form metric values
	//                     (composeCVSSVector graceful-degrades to ""
	//                     on unknown values)
	//   - AdditionalCWEs← cwes[1:] when multi-CWE; LOAD-BEARING for
	//                     SPEC §8.2 forward-pin per ADR-024 §3.1.4
	cweIDs := jsonx.ExtractStringSlice(v, "cwes")
	cweID := jsonx.FirstString(cweIDs)
	var additionalCWEs []string
	if len(cweIDs) > 1 {
		additionalCWEs = cweIDs[1:]
	}

	references := extractReferenceURLs(v)
	cvssVector := composeCVSSVector(cvssV3{
		AttackVector:          jsonx.ExtractString(cvssv3, "attackVector"),
		AttackComplexity:      jsonx.ExtractString(cvssv3, "attackComplexity"),
		PrivilegesRequired:    jsonx.ExtractString(cvssv3, "privilegesRequired"),
		UserInteraction:       jsonx.ExtractString(cvssv3, "userInteraction"),
		Scope:                 jsonx.ExtractString(cvssv3, "scope"),
		ConfidentialityImpact: jsonx.ExtractString(cvssv3, "confidentialityImpact"),
		IntegrityImpact:       jsonx.ExtractString(cvssv3, "integrityImpact"),
		AvailabilityImpact:    jsonx.ExtractString(cvssv3, "availabilityImpact"),
	})

	return events.RawFinding{
		Title:          name,
		Description:    description,
		Severity:       mapSeverity(jsonx.ExtractString(v, "severity")),
		FindingType:    name,
		CWEID:          cweID,
		CVSSScore:      score,
		CodeFile:       filePath,
		References:     references,
		CVSSVector:     cvssVector,
		AdditionalCWEs: additionalCWEs,
	}
}

// extractReferenceURLs walks v["references"] expecting an array of
// {"url": "...", "name": "...", "source": "..."} objects (Dep-Check
// per-CVE reference shape) and returns the extracted URLs. Returns
// nil if absent or empty.
func extractReferenceURLs(v map[string]any) []string {
	refs, ok := v["references"].([]any)
	if !ok || len(refs) == 0 {
		return nil
	}
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if url := jsonx.ExtractString(rm, "url"); url != "" {
			out = append(out, url)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
