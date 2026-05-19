// Package trivy implements the Task 7.1 Trivy consumer — exec-shape
// DockerRunner consumer per ADR-026 framework + Q2-locked dual
// registration (TrivyContainerScanner Category "container" +
// TrivyFsScanner Category "sca"). Mirrors Task 7.2 Nmap precedent
// (commit 872b2b0) for package layout + parser conventions.
//
// Per Phase 0 v2 empirical verification (aquasec/trivy:0.70.0
// @sha256:be1190af...961a41e) against alpine:3.10 image-mode +
// /tmp/trivy-fs-test/ fs-mode targets; JSON schema verified;
// DRIFT-A1 (additional top-level fields ReportID/Trivy/CreatedAt/
// ArtifactID), DRIFT-A2 (per-result Packages[] field), DRIFT-B1
// (PkgPath not per-vuln; subpath via PURL), DRIFT-B2 (multi-vendor
// CVSS map; no scalar CVSSScore), DRIFT-B3 (rich per-vuln metadata)
// all surfaced + locked at X1+X2+X3 per implementation plan §3.
//
// encoding/json default-ignore-unknown-fields handles DRIFT-A1/A2
// forward-additive shape transparently; struct definitions capture
// only the fields the parser consumes.
package trivy

// TrivyOutput is the top-level Trivy JSON document
// (`trivy image|fs --format json`). Per Phase 0 v2 V2 verification
// against v0.70.0; SchemaVersion 2 confirmed.
type TrivyOutput struct {
	SchemaVersion int            `json:"SchemaVersion"`
	ArtifactName  string         `json:"ArtifactName"`           // scan target identifier (image ref or fs path)
	ArtifactType  string         `json:"ArtifactType"`           // "container_image" | "filesystem"
	Metadata      *TrivyMetadata `json:"Metadata,omitempty"`     // image-mode populated; fs-mode absent
	Results       []TrivyResult  `json:"Results"`
}

// TrivyMetadata is the image-mode metadata block. Fs-mode emits an
// empty Metadata object OR omits it entirely. Per DRIFT-A1: additional
// fields (Size, ImageID, DiffIDs, RepoTags, RepoDigests, Reference,
// ImageConfig) decoded as unknown and silently ignored.
type TrivyMetadata struct {
	OS     *TrivyOS     `json:"OS,omitempty"`
	Layers []TrivyLayer `json:"Layers,omitempty"`
}

// TrivyOS captures the image's base OS Family + Name. Container-mode
// only; populates Metadata.os_family + os_version keys per X3 lock.
type TrivyOS struct {
	Family string `json:"Family"` // e.g. "alpine" | "debian" | "ubuntu"
	Name   string `json:"Name"`   // e.g. "3.10.9" | "11.5"
}

// TrivyLayer represents a single image layer. Currently consumed only
// for image-mode Metadata.layer_digest key population (top-layer digest
// not authoritatively mapped to per-vuln Layer field; per-vuln Layer
// preferred when present).
type TrivyLayer struct {
	Digest string `json:"Digest"`
	DiffID string `json:"DiffID"`
}

// TrivyResult is one section result (per scan target / package class).
// Per Q7 lock + Phase 0 v2 V5 fs-mode verification: structurally
// uniform across both modes; flat parser iteration suffices.
//
// Class enumeration (Phase 0 v2): "os-pkgs" | "lang-pkgs".
// Type enumeration (Phase 0 v2): "alpine" | "debian" | "bundler" |
// "npm" | "pip" | etc. (forward-additive; not enumerated exhaustively).
type TrivyResult struct {
	Target          string              `json:"Target"`              // e.g. "alpine:3.10 (alpine 3.10.9)" or "Gemfile.lock"
	Class           string              `json:"Class"`
	Type            string              `json:"Type"`
	Vulnerabilities []TrivyVulnerability `json:"Vulnerabilities,omitempty"`
}

// TrivyVulnerability is a single CVE finding within a Result.
// Per Phase 0 v2 V2: per-vuln field set verified against alpine:3.10
// + fs-mode multi-manifest fixtures.
type TrivyVulnerability struct {
	VulnerabilityID  string              `json:"VulnerabilityID"`    // e.g. "CVE-2021-36159"
	PkgID            string              `json:"PkgID,omitempty"`    // e.g. "apk-tools@2.10.6-r0"
	PkgName          string              `json:"PkgName"`            // populates ComponentName per Q6 typed-field reuse
	PkgIdentifier    TrivyPkgIdentifier  `json:"PkgIdentifier"`      // PURL + UID per DRIFT-B1 X1 PURL-parse disposition
	InstalledVersion string              `json:"InstalledVersion,omitempty"`
	FixedVersion     string              `json:"FixedVersion,omitempty"`
	Status           string              `json:"Status,omitempty"`   // "fixed" | "affected" | ...
	Layer            *TrivyLayer         `json:"Layer,omitempty"`    // image-mode populated; fs-mode absent
	SeveritySource   string              `json:"SeveritySource,omitempty"`
	PrimaryURL       string              `json:"PrimaryURL,omitempty"` // per X3 Phase 0 v2 NEW Metadata key
	DataSource       *TrivyDataSource    `json:"DataSource,omitempty"`
	Title            string              `json:"Title,omitempty"`
	Description      string              `json:"Description,omitempty"`
	Severity         string              `json:"Severity"`           // UPPERCASE: UNKNOWN|LOW|MEDIUM|HIGH|CRITICAL
	CweIDs           []string            `json:"CweIDs,omitempty"`   // first → CWEID typed field; remainder → AdditionalCWEs per Q6
	CVSS             map[string]TrivyCVSS `json:"CVSS,omitempty"`    // vendor-keyed map per DRIFT-B2 X2 vendor-priority chain
	References       []string            `json:"References,omitempty"` // typed RawFinding.References per Y3 typed-field expansion
}

// TrivyPkgIdentifier carries the package URL + unique ID. PURL is
// industry-standard package URL form (pkg:type/namespace/name@version
// [?qualifiers][#subpath]); per X1 lock, parsed for `pkg_path` Metadata
// key via extractPkgPathFromPURL helper.
type TrivyPkgIdentifier struct {
	PURL string `json:"PURL,omitempty"`
	UID  string `json:"UID,omitempty"`
}

// TrivyCVSS holds per-vendor scoring entries. Phase 0 v2 confirmed
// multi-vendor map shape; per X2 vendor-priority chain
// (nvd.V3 → redhat.V3 → ghsa.V3 → nvd.V2 → 0) populates both
// RawFinding.CVSSScore + RawFinding.CVSSVector (typed; Y3 expansion).
type TrivyCVSS struct {
	V2Vector string  `json:"V2Vector,omitempty"`
	V3Vector string  `json:"V3Vector,omitempty"`
	V2Score  float64 `json:"V2Score,omitempty"`
	V3Score  float64 `json:"V3Score,omitempty"`
}

// TrivyDataSource is the per-vuln vulnerability data origin (e.g.
// alpine secdb, GitHub Security Advisories). Not currently surfaced
// to RawFinding; reserved for future Metadata enrichment forward-pin
// (`data_source` candidate per implementation plan §3.3).
type TrivyDataSource struct {
	ID   string `json:"ID,omitempty"`
	Name string `json:"Name,omitempty"`
	URL  string `json:"URL,omitempty"`
}

