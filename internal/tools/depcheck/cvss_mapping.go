// Package depcheck CVSS 3.1 vector composition.
//
// Dep-Check emits CVSS v3 metric values as full uppercase words
// (e.g., "NETWORK"); CVSS canonical specification uses single-letter
// codes (e.g., "N"). This file provides the authoritative
// word→letter mapping per FIRST.org CVSS v3.1 Specification Document.
//
// Composed canonical vector format:
//
//	"CVSS:3.1/AV:<X>/AC:<X>/PR:<X>/UI:<X>/S:<X>/C:<X>/I:<X>/A:<X>"
//
// Per ADR-024 (M6-close-followup): CVSSVector is reserved for future
// SPEC §8.3 exploitability_multiplier derivation. The vector is
// stored as-emitted; no parsing into 8-dimension subfields at SPEC
// §7.3 time.
package depcheck

import "fmt"

// cvssV3 represents the per-CVE CVSS 3.x metric values as emitted
// by Dep-Check JSON. Field types are Dep-Check's uppercase-word
// convention; mapped to canonical single-letter codes in
// composeCVSSVector.
type cvssV3 struct {
	AttackVector          string // NETWORK / ADJACENT_NETWORK / LOCAL / PHYSICAL
	AttackComplexity      string // LOW / HIGH
	PrivilegesRequired    string // NONE / LOW / HIGH
	UserInteraction       string // NONE / REQUIRED
	Scope                 string // UNCHANGED / CHANGED
	ConfidentialityImpact string // NONE / LOW / HIGH
	IntegrityImpact       string // NONE / LOW / HIGH
	AvailabilityImpact    string // NONE / LOW / HIGH
}

// cvssWordToLetter maps Dep-Check's uppercase-word values to CVSS
// 3.1 canonical single-letter codes per FIRST.org spec.
//
// Each dimension has its own mapping subtable to avoid ambiguity
// (e.g., "NONE" maps to "N" for PR/UI/Impact, but the dimensions
// are distinct per CVSS spec).
var cvssWordToLetter = map[string]map[string]string{
	"AttackVector": {
		"NETWORK":          "N",
		"ADJACENT_NETWORK": "A",
		"LOCAL":            "L",
		"PHYSICAL":         "P",
	},
	"AttackComplexity": {
		"LOW":  "L",
		"HIGH": "H",
	},
	"PrivilegesRequired": {
		"NONE": "N",
		"LOW":  "L",
		"HIGH": "H",
	},
	"UserInteraction": {
		"NONE":     "N",
		"REQUIRED": "R",
	},
	"Scope": {
		"UNCHANGED": "U",
		"CHANGED":   "C",
	},
	"ConfidentialityImpact": {
		"NONE": "N",
		"LOW":  "L",
		"HIGH": "H",
	},
	"IntegrityImpact": {
		"NONE": "N",
		"LOW":  "L",
		"HIGH": "H",
	},
	"AvailabilityImpact": {
		"NONE": "N",
		"LOW":  "L",
		"HIGH": "H",
	},
}

// composeCVSSVector builds the canonical CVSS 3.1 vector string
// from Dep-Check's word-form metric values.
//
// Returns empty string if any dimension fails to map (graceful
// degradation: prefer empty CVSSVector to malformed string). Future
// enhancement: surface mapping failures via logger if debugging
// needed.
func composeCVSSVector(v cvssV3) string {
	av, ok1 := cvssWordToLetter["AttackVector"][v.AttackVector]
	ac, ok2 := cvssWordToLetter["AttackComplexity"][v.AttackComplexity]
	pr, ok3 := cvssWordToLetter["PrivilegesRequired"][v.PrivilegesRequired]
	ui, ok4 := cvssWordToLetter["UserInteraction"][v.UserInteraction]
	s, ok5 := cvssWordToLetter["Scope"][v.Scope]
	c, ok6 := cvssWordToLetter["ConfidentialityImpact"][v.ConfidentialityImpact]
	i, ok7 := cvssWordToLetter["IntegrityImpact"][v.IntegrityImpact]
	a, ok8 := cvssWordToLetter["AvailabilityImpact"][v.AvailabilityImpact]

	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 || !ok7 || !ok8 {
		return ""
	}

	return fmt.Sprintf("CVSS:3.1/AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s",
		av, ac, pr, ui, s, c, i, a)
}
