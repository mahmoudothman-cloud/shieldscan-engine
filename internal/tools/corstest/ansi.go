package corstest

import "regexp"

// ansiRE matches ANSI CSI (Control Sequence Introducer) escape codes
// of the form ESC [ <numbers/semicolons> m.
//
// CORStest emits these for color-coding finding lines on terminals.
// The parser strips them before extracting structured data per
// DRIFT-LOG M6.6 entry 9.
//
// Pattern: \x1b is ESC; \[ is literal; [0-9;]* matches the parameter
// bytes (digits + semicolons); m is the SGR (Select Graphic
// Rendition) terminator.
//
// This regex matches the SGR family only (most common in CLI tool
// output). Other CSI families (cursor movement, screen clearing) use
// different terminators (H, J, K, etc.); CORStest doesn't emit them
// in normal scan output. Trigger to extend: customer report of
// non-SGR escapes leaking into findings.
var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// stripANSI removes ANSI escape sequences from s. Returns s unchanged
// if no escape codes present.
//
// Used by the parser before extracting structured data from each
// CORStest output line.
func stripANSI(s string) string {
	return ansiRE.ReplaceAllString(s, "")
}
