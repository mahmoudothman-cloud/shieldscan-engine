package depcheck

import "testing"

func TestComposeCVSSVector_FullNetworkVector(t *testing.T) {
	v := cvssV3{
		AttackVector:          "NETWORK",
		AttackComplexity:      "LOW",
		PrivilegesRequired:    "NONE",
		UserInteraction:       "NONE",
		Scope:                 "UNCHANGED",
		ConfidentialityImpact: "HIGH",
		IntegrityImpact:       "HIGH",
		AvailabilityImpact:    "HIGH",
	}
	got := composeCVSSVector(v)
	want := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestComposeCVSSVector_LocalScope(t *testing.T) {
	v := cvssV3{
		AttackVector:          "LOCAL",
		AttackComplexity:      "HIGH",
		PrivilegesRequired:    "HIGH",
		UserInteraction:       "REQUIRED",
		Scope:                 "CHANGED",
		ConfidentialityImpact: "LOW",
		IntegrityImpact:       "NONE",
		AvailabilityImpact:    "LOW",
	}
	got := composeCVSSVector(v)
	want := "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:N/A:L"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestComposeCVSSVector_AdjacentNetwork(t *testing.T) {
	v := cvssV3{
		AttackVector:          "ADJACENT_NETWORK",
		AttackComplexity:      "LOW",
		PrivilegesRequired:    "LOW",
		UserInteraction:       "NONE",
		Scope:                 "UNCHANGED",
		ConfidentialityImpact: "HIGH",
		IntegrityImpact:       "LOW",
		AvailabilityImpact:    "NONE",
	}
	got := composeCVSSVector(v)
	want := "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestComposeCVSSVector_PhysicalAttackVector(t *testing.T) {
	v := cvssV3{
		AttackVector:          "PHYSICAL",
		AttackComplexity:      "LOW",
		PrivilegesRequired:    "NONE",
		UserInteraction:       "REQUIRED",
		Scope:                 "UNCHANGED",
		ConfidentialityImpact: "LOW",
		IntegrityImpact:       "LOW",
		AvailabilityImpact:    "LOW",
	}
	got := composeCVSSVector(v)
	want := "CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestComposeCVSSVector_EmptyOnUnknownValue(t *testing.T) {
	v := cvssV3{
		AttackVector:          "INVALID_VALUE", // unknown; should fail
		AttackComplexity:      "LOW",
		PrivilegesRequired:    "NONE",
		UserInteraction:       "NONE",
		Scope:                 "UNCHANGED",
		ConfidentialityImpact: "HIGH",
		IntegrityImpact:       "HIGH",
		AvailabilityImpact:    "HIGH",
	}
	got := composeCVSSVector(v)
	if got != "" {
		t.Errorf("expected empty string on unknown value; got %q", got)
	}
}

func TestComposeCVSSVector_EmptyOnAllEmpty(t *testing.T) {
	v := cvssV3{}
	got := composeCVSSVector(v)
	if got != "" {
		t.Errorf("expected empty string when all dimensions empty; got %q", got)
	}
}

func TestCVSSWordToLetterMap_AllDimensionsPresent(t *testing.T) {
	expectedDimensions := []string{
		"AttackVector", "AttackComplexity", "PrivilegesRequired",
		"UserInteraction", "Scope", "ConfidentialityImpact",
		"IntegrityImpact", "AvailabilityImpact",
	}
	for _, dim := range expectedDimensions {
		if _, ok := cvssWordToLetter[dim]; !ok {
			t.Errorf("dimension %q missing from cvssWordToLetter map", dim)
		}
	}
}

func TestCVSSWordToLetterMap_AttackVectorComplete(t *testing.T) {
	want := map[string]string{
		"NETWORK":          "N",
		"ADJACENT_NETWORK": "A",
		"LOCAL":            "L",
		"PHYSICAL":         "P",
	}
	for word, letter := range want {
		got, ok := cvssWordToLetter["AttackVector"][word]
		if !ok {
			t.Errorf("AttackVector[%q] missing", word)
		}
		if got != letter {
			t.Errorf("AttackVector[%q]: got %q, want %q", word, got, letter)
		}
	}
}
