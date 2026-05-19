package trivy

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/odyssey/shieldscan-engine/internal/events"
)

// parseTrivyJSON is the top-level parser per Q7 uniform Results[]
// flat-shape lock + C5 typed-fields-first + Metadata-for-remainder
// convention. Iterates every Result's Vulnerabilities[]; each vuln
// becomes one RawFinding via buildVulnFinding.
//
// Identity-field delegation per ToolRunner interface contract
// (internal/tools/runner.go): ToolName + EngineCategory + DiscoveredAt
// + Fingerprint populated by the DockerRunner framework AFTER parse;
// ScanID + OrgID populated by the processor (Task 5.5). This parser
// leaves those fields empty per docstring symmetric with Nmap
// precedent (internal/tools/docker/nmap/parser.go).
//
// A scan with zero vulnerabilities returns ([], nil); a malformed
// JSON document returns (nil, error) — symmetric with Nmap parser
// error semantics.
func parseTrivyJSON(stdout []byte) ([]events.RawFinding, error) {
	var doc TrivyOutput
	if err := json.Unmarshal(stdout, &doc); err != nil {
		return nil, fmt.Errorf("trivy: json parse: %w", err)
	}
	// image-mode os_family/os_version values extracted once per scan
	osFamily, osVersion := "", ""
	if doc.Metadata != nil && doc.Metadata.OS != nil {
		osFamily = doc.Metadata.OS.Family
		osVersion = doc.Metadata.OS.Name
	}
	var findings []events.RawFinding
	for _, result := range doc.Results {
		for _, vuln := range result.Vulnerabilities {
			findings = append(findings, buildVulnFinding(
				result, vuln, doc.ArtifactName, doc.ArtifactType, osFamily, osVersion,
			))
		}
	}
	return findings, nil
}

// buildVulnFinding maps one Trivy vulnerability to one RawFinding.
// Typed-fields-first per C5 convention (Nmap + ZAP + MobSF precedent;
// SPEC §13 ADR-027 + ToolRunner interface contract are canonical
// authorities — see Phase 5.D 1c6041d "not-duplicative" criterion).
//
// Y3 typed-field expansion (Phase 1 PRE-P1 verification):
//   - References → events.RawFinding.References (ADR-024 typed; not
//     Metadata)
//   - CVSSVector → events.RawFinding.CVSSVector (ADR-024 typed; not
//     Metadata); matches the vendor that produced CVSSScore per X2
//   - CWEs: first → CWEID; remainder → AdditionalCWEs (per Q6 +
//     ADR-024 typed-field set)
//
// Q6 evidence-cluster reuse (no new typed-field promotion):
//   - PkgName → ComponentName (lifted from MobSF Task 7.4)
//   - extractCVSSScore vendor-priority result → CVSSScore (lifted)
func buildVulnFinding(
	result TrivyResult,
	vuln TrivyVulnerability,
	artifactName, artifactType, osFamily, osVersion string,
) events.RawFinding {
	severity := mapTrivySeverity(vuln.Severity)

	title := vuln.Title
	if title == "" {
		title = vuln.VulnerabilityID
	}

	// CWE distribution: first → typed CWEID; rest → AdditionalCWEs
	var cweID string
	var additionalCWEs []string
	if len(vuln.CweIDs) > 0 {
		cweID = vuln.CweIDs[0]
		if len(vuln.CweIDs) > 1 {
			additionalCWEs = vuln.CweIDs[1:]
		}
	}

	score, vendor := extractCVSSScore(vuln.CVSS)
	cvssVector := extractCVSSVector(vuln.CVSS, vendor)

	finding := events.RawFinding{
		Title:          title,
		Severity:       severity,
		Description:    vuln.Description,
		FindingType:    "vulnerability",
		CWEID:          cweID,
		AdditionalCWEs: additionalCWEs,
		CVSSScore:      score,
		CVSSVector:     cvssVector,
		References:     vuln.References,
		ComponentName:  vuln.PkgName,
		Metadata: buildMetadata(
			result, vuln, artifactName, artifactType, osFamily, osVersion,
		),
	}
	return finding
}

// buildMetadata assembles the snake_case Metadata map per ADR-027
// + Phase 0 v2 X3 + Y3 routing. Omit-when-empty discipline applied to
// every key.
//
// Metadata key contract (Task 7.1 v1; per implementation plan §3.3
// X3 + Y3 typed-field expansion correction):
//
// ADR-027 canonical (per SPEC §13):
//   - component_name, component_version, package_manager
//
// (license + installed_path forward-pinned; license not surfaced by
// Trivy v0.70.0 JSON output unless --license-full passed; installed_path
// future-additive)
//
// SCA-specific (this consumer):
//   - pkg_path (from X1 PURL parse), installed_version, fixed_version,
//     vulnerability_id, target (correlation key per C5), class, type,
//     status
//
// Container-specific (image-mode only; populated via per-vuln Layer
// when present + image-level OS from doc.Metadata.OS):
//   - layer_digest, os_family, os_version
//
// Phase 0 v2 NEW (X3 conservative extension):
//   - purl, primary_url
//
// Y3 typed-field promotion REMOVES these from Metadata (now typed):
//   - references → RawFinding.References
//   - cvss_vector → RawFinding.CVSSVector
func buildMetadata(
	result TrivyResult,
	vuln TrivyVulnerability,
	artifactName, artifactType, osFamily, osVersion string,
) map[string]string {
	m := map[string]string{}
	setIfNonEmpty(m, "component_name", vuln.PkgName)
	setIfNonEmpty(m, "component_version", vuln.InstalledVersion)
	setIfNonEmpty(m, "package_manager", result.Type)
	setIfNonEmpty(m, "installed_version", vuln.InstalledVersion)
	setIfNonEmpty(m, "fixed_version", vuln.FixedVersion)
	setIfNonEmpty(m, "vulnerability_id", vuln.VulnerabilityID)
	setIfNonEmpty(m, "target", result.Target)
	setIfNonEmpty(m, "class", result.Class)
	setIfNonEmpty(m, "type", result.Type)
	setIfNonEmpty(m, "status", vuln.Status)
	setIfNonEmpty(m, "purl", vuln.PkgIdentifier.PURL)
	setIfNonEmpty(m, "primary_url", vuln.PrimaryURL)
	setIfNonEmpty(m, "pkg_path", extractPkgPathFromPURL(vuln.PkgIdentifier.PURL))

	// Container-mode only (per-vuln Layer present + image OS available)
	if artifactType == "container_image" {
		if vuln.Layer != nil {
			setIfNonEmpty(m, "layer_digest", vuln.Layer.Digest)
		}
		setIfNonEmpty(m, "os_family", osFamily)
		setIfNonEmpty(m, "os_version", osVersion)
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

func setIfNonEmpty(m map[string]string, key, value string) {
	if value == "" {
		return
	}
	m[key] = value
}

// mapTrivySeverity maps Trivy's UPPERCASE severity strings to the
// ShieldScan canonical lowercase set (verified at Phase 1 entry against
// mapMobSFSeverity + mapZAPRisk precedents):
//
//	UNKNOWN  → "info"   (defensive: surface rather than drop)
//	LOW      → "low"
//	MEDIUM   → "medium"
//	HIGH     → "high"
//	CRITICAL → "critical"
//
// Convention naming intentional per implementation plan §3.4 Q5 lock:
// mirrors mapZAPRisk + mapMobSFSeverity. Phase 5.D 3rd-instance
// severity-normalization-helper threshold evaluation deferred to
// post-Phase-1 architectural-integration phase per 1c6041d V5.E.3
// forward-pin.
func mapTrivySeverity(severity string) string {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	case "UNKNOWN", "":
		return "info"
	default:
		// Defensive forward-compat: future Trivy versions may add
		// severity buckets; surface as "info" rather than drop.
		return "info"
	}
}

// extractCVSSScore implements X2 vendor-priority chain:
//
//	nvd.V3Score → redhat.V3Score → ghsa.V3Score → nvd.V2Score → 0
//
// Returns the chosen numeric score + the vendor key that produced it
// (so extractCVSSVector can return the matching vector for typed-field
// consistency per Y3).
//
// NVD canonical authority; Red Hat for OS-package CVEs (often
// NVD-absent); GHSA for code-package GitHub-tracked vulnerabilities;
// V2 fallback for legacy CVE entries without V3 scoring.
func extractCVSSScore(cvss map[string]TrivyCVSS) (score float64, vendor string) {
	if cvss == nil {
		return 0, ""
	}
	// V3 priority chain
	for _, v := range []string{"nvd", "redhat", "ghsa"} {
		if entry, ok := cvss[v]; ok && entry.V3Score > 0 {
			return entry.V3Score, v
		}
	}
	// V2 fallback (NVD only per X2)
	if entry, ok := cvss["nvd"]; ok && entry.V2Score > 0 {
		return entry.V2Score, "nvd-v2"
	}
	return 0, ""
}

// extractCVSSVector returns the CVSS vector string from the same
// vendor that produced the CVSSScore (per Y3 typed-field consistency).
// vendor parameter is the second return of extractCVSSScore.
//
// "nvd-v2" vendor key denotes V2 fallback path; returns V2Vector
// from NVD entry rather than V3Vector.
func extractCVSSVector(cvss map[string]TrivyCVSS, vendor string) string {
	if cvss == nil || vendor == "" {
		return ""
	}
	if vendor == "nvd-v2" {
		if entry, ok := cvss["nvd"]; ok {
			return entry.V2Vector
		}
		return ""
	}
	if entry, ok := cvss[vendor]; ok {
		return entry.V3Vector
	}
	return ""
}

// extractPkgPathFromPURL parses the subpath of a Package URL
// (`pkg:type/namespace/name@version[?qualifiers][#subpath]` per the
// PURL specification at github.com/package-url/purl-spec).
//
// Returns the decoded subpath or empty string if PURL absent, scheme
// mismatch, OR no `#subpath` component. Omit-when-empty discipline:
// caller MUST NOT set Metadata["pkg_path"] when this returns "".
//
// Per X1 lock (DRIFT-B1 disposition); empirical Phase 0 v2
// observation: most Trivy PURLs lack #subpath; the helper exists
// primarily for Maven JAR-in-WAR / nested-archive cases where it
// surfaces.
func extractPkgPathFromPURL(purl string) string {
	if purl == "" || !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	hashIdx := strings.LastIndex(purl, "#")
	if hashIdx < 0 || hashIdx == len(purl)-1 {
		return ""
	}
	subpath := purl[hashIdx+1:]
	// PURL spec: subpath is percent-encoded; decode for human-readable
	// Metadata value. On decode failure, return raw (defensive).
	if decoded, err := url.PathUnescape(subpath); err == nil {
		return decoded
	}
	return subpath
}
