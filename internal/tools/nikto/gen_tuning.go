//go:build ignore

// gen_tuning.go generates tuning_table.go from a Nikto installation's
// databases/db_tests file.
//
// Run it whenever Nikto is upgraded — REBUILD-RUNBOOK §3.2 and
// VERSIONS.md §2.5 both point here:
//
//	go run gen_tuning.go -db /home/mahmoud/.local/nikto-2.5.0/databases/db_tests \
//	                     -version 2.5.0 -out tuning_table.go
//
// WHY THIS IS GENERATED AND COMMITTED, rather than read from db_tests at
// worker startup. Reading the database at runtime would stay
// automatically correct as Nikto is upgraded, which is exactly its
// appeal — and exactly the trap. It makes classification depend on the
// state of a file outside the repo, on one host, invisible to review and
// to a rebuild. That is the same shape as the hand-edited FAILURES in
// nikto.conf: a load-bearing value that lived only on the box, survived
// no rebuild, and could not be seen from the source tree. Hermetic beats
// automatically-correct when "automatically" means "depends on the box".
//
// The cost of that choice is a regeneration step on upgrade, and
// TestDBTestTuning_EveryIDResolvesToExactlyOneClass is the forcing
// function that keeps it honest: a table that goes stale in a way that
// matters fails the suite rather than silently misclassifying.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// testLine extracts the two fields this generator needs — the test id
// and the tuning field — from a db_tests row.
//
// db_tests documents its field order in its own header comment:
//
//	Test-ID, References, Tuning Type, URI, HTTP Method, Match 1,
//	Match 1 Or, Match 1 And, Fail 1, Fail 2, Summary, HTTP Data, Headers
//
// This is deliberately NOT a CSV parse. Nikto's match fields contain
// backslash-escaped quotes (`\"`) that are not valid CSV quoting, and
// encoding/csv silently mangles those rows even with LazyQuotes: the
// first attempt at this generator lost 8 tests that way — 006211,
// 006669, 006670, 006986, 007022, 007040, 007280, 007322 — each of
// which would have fallen back to a raw "nikto-<id>" FindingType, which
// is the exact failure this table exists to remove. The id and the
// tuning field are the first and third columns, ahead of anything
// quoted strangely, so anchoring at the start of the line reads them
// from every row. Measured: 6951/6951 rows on 2.5.0.
//
// The tuning character class is permissive on purpose (2.1.5 ships a
// "3bz", with a z that appears in no legend). Extraction is loose;
// validation is strict — see the legend check in parseDB.
var testLine = regexp.MustCompile(`^"(\d+)","[^"]*","([0-9a-z]+)",`)

func main() {
	dbPath := flag.String("db", "", "path to a Nikto installation's databases/db_tests")
	version := flag.String("version", "", "Nikto version the database came from (e.g. 2.5.0)")
	out := flag.String("out", "tuning_table.go", "output file")
	flag.Parse()

	if *dbPath == "" || *version == "" {
		fmt.Fprintln(os.Stderr, "both -db and -version are required")
		os.Exit(2)
	}

	entries, err := parseDB(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse %s: %v\n", *dbPath, err)
		os.Exit(1)
	}
	if len(entries) == 0 {
		fmt.Fprintf(os.Stderr, "%s yielded no tests; refusing to write an empty table\n", *dbPath)
		os.Exit(1)
	}

	src := render(entries, *version, *dbPath)
	if err := os.WriteFile(*out, []byte(src), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", *out, err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s: %d tests from Nikto %s\n", *out, len(entries), *version)
}

type entry struct {
	id     string
	tuning byte // FIRST character of the tuning field — see render's comment
	raw    string
}

// knownTuning is the category legend db_tests documents in its own
// header. It is duplicated here as a VALIDATION gate, not as naming: a
// tuning character Nikto has invented since this table was last
// generated must stop the build rather than quietly produce a class
// nobody has named. tuningClassSlug in classify.go holds the names and
// must be extended in step.
const knownTuning = "0123456789abcdef"

// parseDB reads every test row. It returns an error rather than
// skipping anything: a row this generator cannot read becomes a test
// that classifies as a bare id at runtime, which is the failure the
// table exists to remove, and silently emitting a shorter table is the
// worst way to find that out.
func parseDB(path string) ([]entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var entries []entry
	seen := map[string]string{}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024) // some rows are long
	for lineNo := 1; sc.Scan(); lineNo++ {
		line := sc.Text()
		// Skip ONLY what db_tests legitimately contains besides rows:
		// comments and blank lines. Anything else falls through to the
		// row parse and fails there. An earlier version skipped every
		// line that did not start with a quote, which silently swallowed
		// malformed content — the same "quietly produce a shorter table"
		// failure the CSV parse produced, arrived at from the other side.
		if trimmed := strings.TrimSpace(line); trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		m := testLine.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("%s:%d: cannot read id+tuning from %.80q", path, lineNo, line)
		}
		id, tuning := m[1], m[2]
		if !strings.ContainsRune(knownTuning, rune(tuning[0])) {
			return nil, fmt.Errorf(
				"%s:%d: test %s has tuning %q, whose leading character is not in the "+
					"known legend %q — Nikto has added a category; name it in "+
					"tuningClassSlug (classify.go) before regenerating",
				path, lineNo, id, tuning, knownTuning)
		}
		// A duplicate id with a CONFLICTING tuning would make the map's
		// contents depend on row order. Nikto has never shipped one; fail
		// loudly rather than generate something order-dependent.
		if prev, dup := seen[id]; dup {
			if prev != tuning {
				return nil, fmt.Errorf(
					"%s:%d: id %s appears twice with different tuning (%q then %q); "+
						"the table would depend on row order", path, lineNo, id, prev, tuning)
			}
			continue
		}
		seen[id] = tuning
		entries = append(entries, entry{id: id, tuning: tuning[0], raw: tuning})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].id < entries[j].id })
	return entries, nil
}

func render(entries []entry, version, dbPath string) string {
	multi := 0
	byClass := map[byte]int{}
	for _, e := range entries {
		byClass[e.tuning]++
		if len(e.raw) > 1 {
			multi++
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, `// Code generated by gen_tuning.go; DO NOT EDIT.
//
// Source:  %s
// Nikto:   %s
// Tests:   %d (%d carry a multi-valued tuning field; see below)
//
// Regenerate with:
//
//	go generate ./internal/tools/nikto/
//
// Each entry maps a Nikto db_tests id to the FIRST CHARACTER of that
// test's tuning field, which is Nikto's own category for the check.
// tuningClassSlug (classify.go) turns that character into a
// FindingType; the naming lives there deliberately, so that this file
// holds only facts copied out of Nikto and none of our judgement.
//
// FIRST CHARACTER IS A CHOSEN DEFAULT, NOT A FACT. Nikto's tuning field
// is a SET: %d of %d tests (%.1f%%) carry more than one character, from
// pairs like "1b" up to "1234576890ab", which is every category at once.
// Nikto itself treats the field as a membership test — it is matched
// against the -Tuning flag — so no single category is canonical and
// there is no "primary" the data can be asked for.
//
// Two alternatives were considered and not taken:
//
//   - Most-severe character. Would need a severity ordering over the 16
//     categories, which is precisely the judgement call deliberately
//     deferred (see the severity note in classify.go). It would also
//     make every FindingType depend on that ordering, so revisiting the
//     ordering later would silently move existing fingerprints.
//   - A compound class ("interesting-file+software-identification").
//     Honest, but it multiplies the class space by the observed
//     combinations, and a fingerprint built on it moves whenever Nikto
//     adds a category to an existing test — which the 2.1.5-to-2.5.0
//     diff shows it does.
//
// First-character was chosen because it is stable (99.1%% of ids shared
// between the 2012 and 2026 databases kept an identical tuning field)
// and because the leading character is in practice the one that
// describes the check. Revisit if a future Nikto reorders the field.

package nikto

// dbTestTuning maps a db_tests id to its category character. Ids in
// this table come from Nikto's test database; ids reported by Nikto's
// PLUGINS are a disjoint set handled by the curated classifications in
// classify.go (measured: 77 plugin ids, 0 overlap with these).
var dbTestTuning = map[string]byte{
`, dbPath, version, len(entries), multi, multi, len(entries),
		100*float64(multi)/float64(len(entries)))

	for _, e := range entries {
		fmt.Fprintf(&b, "\t%q: %q,\n", e.id, e.tuning)
	}
	b.WriteString("}\n")
	return b.String()
}
