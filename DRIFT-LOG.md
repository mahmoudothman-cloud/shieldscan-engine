# shieldscan-engine — DRIFT-LOG

Engine-side design decisions, version drift, and pattern bootstraps.
Newest entries on top.

For cross-cutting decisions affecting both `shieldscan-api` and
`shieldscan-engine`, see `../shieldscan-docs/DRIFT-LOG.md`.

---

### 2026-05-03 — M6-close-followup Phase 3: SPEC §7.3 schema extension — Engine struct + 6-tool retrofit

**Phase 3 of M6-close-followup task.** Engine commit follows Phase 1 (shieldscan-docs ADR-024 + SPEC §7.3 update at `59b0f3d` + `8f90531`) and Phase 2 (shieldscan-api SQLAlchemy model + Alembic migration at `938ae80`). Cross-repo coordination per ADR-024 strict-ordering rule (Docs → Python → Engine).

**Files shipped (single atomic engine commit):**
- `internal/events/events.go` — `RawFinding` struct extended with 4 new fields (References, Tags, CVSSVector, AdditionalCWEs); all `omitempty`; backward-compatible.
- `internal/events/events_test.go` — 2 new tests (roundtrip + omitempty regression guard) + extended fixture-decode assertions.
- `internal/events/testdata/job_completed_python_v1.json` — 1st finding populated with all 4 new fields; 2nd finding left bare (omitempty regression guard).
- `internal/tools/jsonx/jsonx.go` — 7th helper added: `FilterEngineCategoryTags`. Promoted at SPEC §7.3 followup per the project's three-instance-threshold convention (4 callsites: Nuclei + Semgrep + Gitleaks + Wapiti).
- `internal/tools/jsonx/jsonx_test.go` — 8-case table-driven test for `FilterEngineCategoryTags`.
- `internal/tools/depcheck/cvss_mapping.go` — NEW. CVSS 6-dimension word→letter mapping table per FIRST.org CVSS v3.1 Specification Document; `composeCVSSVector` graceful-degrades to "" on unknown values.
- `internal/tools/depcheck/cvss_mapping_test.go` — NEW. 8 tests covering full vectors, word→letter mappings, graceful degradation, and map-completeness invariants.
- 6 tool retrofits (`parse.go` + `*_test.go`): Nuclei, Semgrep, Gitleaks, Dep-Check, Checkov, Wapiti.

**3 tools NOT retrofitted** per ADR-024 §3.4: SSLyze (plugin-rules synthesizes findings; no upstream metadata), Nikto (XML emits description-only), CORStest (text-with-ANSI parser extracts URL/origin/headers only). Their reductions stay folded.

**Test counts (engine-wide, post-Phase-3):** all 19 packages green under `go test -race -count=1`. golangci-lint v2.11.4 reports 0 issues. Net-new tests at Phase 3: ~17 (2 events + 1 jsonx + 8 cvss_mapping + 6 across tool retrofits).

**6-tool retrofit outcomes** (per ADR-024 §3.4 retrofit checklist + design doc §4):

| Tool | New fields populated | Reductions rescued |
|---|---|---|
| Nuclei | References + Tags + CVSSVector | 3 → 0 |
| Semgrep | References + Tags (metadata-dependent) | 0–2 (existing baseline 0) |
| Gitleaks | Tags | 5 → 4 (commit-metadata + entropy/columns/endline still folded) |
| Dep-Check | References + CVSSVector + AdditionalCWEs | 5 → 2 (vulnerableSoftware/hashes/evidenceCollected still dropped) |
| Checkov | References (from `guideline`) | 6 → 5 |
| Wapiti | References (`wstg`) + Tags (`module`) | 5 → 3 |

**Reductions counter post-§7.3: 8/9 tools (89%) STILL with reductions.** Per-tool fold counts reduced; no tool's folds eliminated to zero. Trigger remains fired per ADR-024 trigger #3 (future incremental schema extensions may address tool-specific metadata when M7+ data informs which patterns warrant first-class fields).

**AdditionalCWEs § 8.2 forward-pin (LOAD-BEARING).** Per ADR-024 §3.1.4: SPEC §8.2 cross-layer correlation algorithm currently uses `cwe_id` singular. M9 implementation MUST extend the `cwe_exact` / `cwe_parent` checks to consider intersection with `additional_cwes` ({primary} ∪ AdditionalCWEs). Without this extension, M9 misses multi-CWE matches — especially Dep-Check, which routinely emits 2–4 CWEs per CVE. Engine emission populates AdditionalCWEs from `cwes[1:]` for both Nuclei (rare multi-CWE) and Dep-Check (routine multi-CWE); M9 consumer-side algorithm extension lands when M9 implementation arrives.

### 2026-05-03 — M6-close-followup: jsonx 7th helper — `FilterEngineCategoryTags` (3-instance threshold met cleanly)

**Pin.** `internal/tools/jsonx/jsonx.go::FilterEngineCategoryTags` added as the 7th helper in the package. Returns a new slice containing only input tags that do NOT match a canonical engine_category value per SPEC §5.3 (13-value enum: dast/sast/sca/mobile/infrastructure/recon/ssl/api/iac/secrets/container/spa/discovery).

Returns `nil` when the filtered slice is empty so callers assign directly to `RawFinding.Tags` and `omitempty` drops the field on the wire (no spurious `"tags":[]`).

**3-instance threshold met cleanly (4 callsites at promotion):** Nuclei + Semgrep + Gitleaks + Wapiti per-tool retrofits all enforce ADR-024 §3.1.2's "Tags MUST NOT duplicate engine_category" invariant via this helper. Per the project's three-instance promotion convention (DEVELOPMENT-PATTERNS preamble), centralizing the engine_category set in `jsonx` keeps the SPEC §5.3 list as a single source of truth — adding a 14th category requires updating one map, not four parsers.

**Cross-repo schema-coordination note.** The `engineCategoryTagSet` mirrors the Python `EngineCategory` enum in `shieldscan-api/src/app/models/raw_findings.py`. If SPEC §5.3 grows, both sides update together (same cross-repo schema-coordination pattern as adding new RawFinding fields per ADR-024).

### 2026-05-03 — M6-close-followup: CVSS 6-dimension word→letter mapping (Dep-Check)

**Pin.** `internal/tools/depcheck/cvss_mapping.go` provides the authoritative CVSS 3.1 word→letter mapping per FIRST.org CVSS v3.1 Specification Document. Dep-Check emits CVSS metric values as full uppercase words (`"NETWORK"`); CVSS canonical uses single-letter codes (`"N"`).

**8 dimensions covered** (per CVSS 3.1 spec):

| Dimension | Word values | Letter codes |
|---|---|---|
| AttackVector | NETWORK / ADJACENT_NETWORK / LOCAL / PHYSICAL | N / A / L / P |
| AttackComplexity | LOW / HIGH | L / H |
| PrivilegesRequired | NONE / LOW / HIGH | N / L / H |
| UserInteraction | NONE / REQUIRED | N / R |
| Scope | UNCHANGED / CHANGED | U / C |
| ConfidentialityImpact | NONE / LOW / HIGH | N / L / H |
| IntegrityImpact | NONE / LOW / HIGH | N / L / H |
| AvailabilityImpact | NONE / LOW / HIGH | N / L / H |

Each dimension has its own subtable to avoid ambiguity (e.g., `"NONE"` maps to `"N"` for PR/UI/Impact, but the dimensions are distinct per CVSS spec).

**Graceful degradation.** `composeCVSSVector` returns `""` if any dimension fails to map (preferring an empty CVSSVector over a malformed string). This handles real-world Dep-Check fixtures where `cvssv3` carries only a partial subset of dimensions (`baseScore` + `attackVector` only is common in older fixtures). The empty result triggers `omitempty` on the wire — backward-compatible with consumers that expect either a complete vector or no vector.

**Future enhancement trigger:** customer report of "expected CVSSVector but got empty" → instrument `composeCVSSVector` with a logger to surface mapping failures by dimension. Not needed at SPEC §7.3 time.

### 2026-05-03 — M6-close-followup: Reductions counter post-§7.3 status (8/9 still with reductions; trigger remains fired)

**Pin.** Per-tool reductions inventory post-Phase-3 (compare to M6-close-followup pre-implementation tally documented in design doc §2.1):

| Tool | Pre-§7.3 folds | Post-§7.3 folds | Rescued |
|---|---|---|---|
| Nuclei | 3 | 0 | 3 |
| Semgrep | 0 | 0 | 0 (baseline) |
| Gitleaks | 5 | 4 | 1 (Tags) |
| SSLyze | 5–6 | 5–6 | 0 (no retrofit) |
| Dep-Check | 5 | 2 | 3 |
| Checkov | 6 | 5 | 1 |
| Nikto | 3 | 3 | 0 (no retrofit) |
| Wapiti | 5 | 3 | 2 |
| CORStest | 2 | 2 | 0 (no retrofit) |
| **Total** | **~38** | **~26** | **~12 (~32%)** |

**Counter remains at 8/9 tools (89%) with reductions** — no tool's fold count dropped to zero. Trigger remains fired per ADR-024 trigger #3.

**Honest accounting.** The brainstorming-time estimate of 66% rescue rate was inaccurate; the realized 32% reflects the categorical-pattern scope (the 4 fields capture cross-tool patterns: References, Tags, CVSSVector, multi-CWE) but does not address tool-specific metadata. Future incremental schema extensions may target NucleiTemplateID + GitleaksRuleID (per-tool identifiers) or surface SSLyze plugin-output structure if M11 dashboard query patterns surface.

### 2026-05-03 — M6-close-followup: 2 new tracked patterns at 1st instance

**Pattern 1 — Multi-repo schema-coordination commits.** Strict-ordering Docs → Python → Engine (Phase 1 / Phase 2 / Phase 3) enforced by ADR-024 to maintain cross-repo schema agreement. The reverse failure mode (Engine ships first; Python rejects unknown fields) doesn't materialize in this instance because Python ingest is deferred (Path A; ADR-024 "Python ingest scope"); but the workflow is exercised end-to-end as the canonical pattern shape for future schema extensions.

- Instance 1: SPEC §7.3 followup (this task).
- Trigger to promote to DEVELOPMENT-PATTERNS: 3rd instance.

**Pattern 2 — Optional-field additive migrations with backward-compat.** Alembic `add_column` with `nullable=True` + Go struct `omitempty` JSON tags. Existing wire-format fixtures parse cleanly without the new fields; existing DB rows accept the new columns as NULL. Forward + backward migration verified at Phase 2.

- Instance 1: SPEC §7.3 followup (this task).
- Trigger to promote to DEVELOPMENT-PATTERNS: 3rd instance.

Both patterns track-only at this stage; ADR-024 documents them for future cross-reference.

### 2026-05-03 — M6-close-followup: asymmetric-cost meta-principle 3rd ADR invocation

**Pin.** ADR-024 is the 3rd ADR in the project corpus to invoke the asymmetric-cost meta-principle to justify an architectural commitment:

| ADR | Architectural commitment | Asymmetric-cost framing |
|---|---|---|
| ADR-022 (M6.3) | Recon-as-pre-scan-helpers, NOT ToolRunner-registered | Cost of forcing recon into ToolRunner > cost of architectural carve-out |
| ADR-023 (M6.7) | NativeRunner OutputFile mode (3-instance threshold OVERRIDDEN) | Cost of race-prone hacks > cost of premature framework abstraction (~50 LoC) |
| ADR-024 (M6-followup) | SPEC §7.3 schema extension (4 fields) | Cost of compounding folds across M7+ tools + missing M9 multi-CWE correlation > cost of cross-repo extension (~4.5–5h post-Path-A) |

**The shared meta-principle, now invoked across three consecutive M6 ADRs, is project corpus norm:** *architectural commitments are made when the alternative is operationally worse, not when a generic threshold is met.*

**Trigger to promote to DEVELOPMENT-PATTERNS:** if a 4th+ ADR invokes the same meta-principle, document the reasoning shape explicitly (when to invoke vs when to defer to threshold-based promotion). 3 instances is the threshold; ADR-024's invocation puts the meta-principle at exactly the promotion bar — but per Pattern 1's "trigger-based deferral" discipline, a 4th instance is desirable to confirm the pattern before formalization.

### 2026-05-03 — M6-close-followup: Phase 0 verification pattern reinforced (3rd instance)

**Pin.** Phase 0 verification before implementation surfaced state-of-repo deviations from pre-phase instructions in two concrete instances during this task:

| Phase | Surface | Outcome |
|---|---|---|
| Phase 0 | Design doc assumed Pydantic schema + CompletionsConsumer ingest path exists; verification confirmed neither does | Path A adoption (Python ingest deferred); ADR-024 "Python ingest scope" subsection codifies |
| Phase 2 Step 1 | Verbatim Alembic migration template assumed `dc5ca2edbd3f` was the head; `alembic heads` confirmed actual head is `d4f6b1e9a527` | Auto-corrected per "factual deviations: auto-correct + document" protocol |

These join two prior project-corpus self-catches (M6.3 httpx stdin pipe; M6.6 Nikto XML support discovery) — collectively the 3rd, 4th, and 5th instances of the empirical-verification-before-implementation discipline.

**Track for promotion.** If a 6th+ instance surfaces, consider DEVELOPMENT-PATTERNS entry "verification-before-implementation" formalizing the discipline:
- Pre-phase instructions are starting points, not guarantees of repo state.
- Phase 0 (or equivalent verification step) is mandatory for cross-repo concerns and any task whose scope depends on assumed system state.
- Mechanical/factual deviations auto-correct + document; architectural deviations surface + pause.

The pattern is operationally critical — without it, a chain of plausible-but-wrong assumptions compounds into Phase 2 / Phase 3 implementation churn.

### 2026-05-03 — Task 6.8 (M6 CLOSE): Registry wiring — 9 ToolRunners registered + recon helper not registered

**M6 CLOSED. 8/8 tasks complete.** This is the canonical M6 retrospective entry. Future engineers reading the M6 milestone shape years from now should be able to reconstruct the milestone from this entry alone.

**Files shipped (single atomic engine commit):**
- NEW `cmd/worker/binary_resolution.go` + `binary_resolution_test.go` (4 tests)
- NEW `cmd/worker/registry_wiring.go` (`buildRegistry` + 9-tool spec table)
- UPDATE `cmd/worker/run.go` (replaces empty `worker.NewRegistry(map[string]tools.ToolRunner{})` from 5.6 with `buildRegistry(log)` call; populates `StartupDeps.NativeTools`)
- UPDATE `cmd/worker/run_test.go` (4 net-new tests + `installMockBinaries` helper + `syncWriter` for log capture)

**No companion docs commit at 6.8.** SPEC §7.3 schema-extension proposal (8/9 tools = 89% with reductions) is queued for a separate M6-close-followup task per H.A — keeps 6.8 focused on the wiring assembly. M6 close is the semantic milestone; SPEC §7.3 is a cross-repo concern deserving its own scope proposal.

**M6 milestone shape (8 tasks; 9 tools across 8 categories; 1 helper; 4 patterns; 2 ADRs):**

| Task | Scope | Tool(s) | Category |
|---|---|---|---|
| 6.1 | Nuclei runner + chassis exercising | nuclei | dast |
| 6.2 | Semgrep runner + per-rule severity | semgrep | sast |
| 6.3 | Subfinder + httpx (recon helpers; NOT ToolRunners per ADR-022) | — | recon |
| 6.4 | Dep-Check + Checkov runners | depcheck, checkov | sca, iac |
| 6.5 | SSLyze runner + plugin-rules + jsonx extraction | sslyze | ssl |
| 6.6 | Nikto + Wapiti + CORStest runners + Pattern 4 promotion | nikto, wapiti, corstest | dast, dast, api |
| 6.7 | Gitleaks runner + NativeRunner OutputFile mode (ADR-023) | gitleaks | secrets |
| 6.8 | Registry wiring (M6 CLOSE) | — | — |

**9 ToolRunners registered alphabetically** (matches `buildRegistry` spec table + DRIFT entry below): `checkov, corstest, depcheck, gitleaks, nikto, nuclei, semgrep, sslyze, wapiti`.

**1 helper package not registered** (`internal/tools/recon`): pre-scan helpers per ADR-022; M8 imports + invokes `recon.RunRecon` directly.

**4 DEVELOPMENT-PATTERNS entries promoted across M6:**
1. Pattern 1 — Trigger-based deferral (5.5; promoted at framework tier; reinforced across M6)
2. Pattern 2 — `SHIELDSCAN_<TOOL>_BINARY` env-var-binary (6.5 promotion; 12 instances by M6 close)
3. Pattern 3 — `PYTHONWARNINGS=ignore` for pipx-Python tools (6.7 promotion; 5 instances by M6 close)
4. Pattern 4 — Constants-only field mapping (6.6 promotion; 4 instances)

**2 ADRs added in M6:**
- ADR-022 — Recon-as-pre-scan-helpers (M6.3): rejects forcing Subfinder/httpx into the ToolRunner contract; codifies architectural distinction between target-discovery data and findings.
- ADR-023 — NativeRunner OutputFile mode (M6.7): bimodal NativeRunner gains `OutputFile`/`OutputFilePlaceholder`/`ParseOutputFile` fields for tools whose JSON-to-stdout is broken (Wapiti `-o /dev/stdout` corruption) or absent (Dep-Check writes to file). 2 consumers by M6 close (Dep-Check + Wapiti).

**Test counts (engine-wide, post-6.8):** 296 tests across 19 packages (292 at 6.6 close + 4 at 6.8). All race-clean, vet-clean, golangci-lint v2.11.4 reports 0 issues.

**Reductions counter at 8/9 (89%).** SPEC §7.3 trigger fired (>50%); proposal scoped + queued for M6-close-followup task per H.A.

**Self-catches accumulated across M5+M6 (load-bearing pattern-velocity examples):**
- M5.5 → ctx-discipline forcing function via goleak
- M6.3 → empirical re-eval reversed inline-tempfile lean (httpx stdin pipe is correct shape)
- M6.6 → empirical re-eval surfaced Nikto XML support (sidestepped fragile text parser)
- M6.7 → Wapiti `-o /dev/stdout` corruption empirically verified, motivated ADR-023
- M6.8 → 5.6 forward-pin (empty-registry WARN) closed; verified by `TestRunMain_NoEmptyRegistryWarning`

**Pattern landscape at M6 close** (for M7 forward-pinning):
- Naturally-clean exit-code: 6 instances (track; promotion deferred per H.NEW.8)
- Domain-rules severity mapping: 2 instances (track for 3rd)
- Plugin-rules parser: 1 instance (SSLyze; track)
- Inline-tempfile workaround: 1 instance (CORStest)
- jsonx helpers: 10 callsites (extracted at 6.5)
- `resolveBinary` helper: 2 instances at different layers (recon package + cmd/worker; H.E preserves placement)

**5.6 forward-pin closed.** The "empty registry warning" guarded by `internal/worker/startup.go` (added at 5.6 with explicit M6 forward-pin) MUST NOT fire post-6.8. Verified by `TestRunMain_NoEmptyRegistryWarning` (log capture asserts substring absence + presence of `registered_engines` Info path).

**M5 chassis + M6 tools end-to-end functional.** Worker process can now: bootstrap with binary verification (Phase 1) → register in Redis (Phase 4) → BRPOP scan jobs → dispatch to one of 9 native runners → stream findings via processor → emit `job_completed`. Ready for M7 (Docker service tools) after SPEC §7.3 followup.

### 2026-05-03 — Task 6.8: Plan §6.8 redefinition (consolidating M6.1/M6.4/M6.6/M6.7 plan-staleness briefs)

**Pin.** Plan §6.8's literal text (written pre-M6) describes "wire all 6 tool runners into the worker.Registry, populate the engine map" with a tool list that doesn't match the M6 outcome. Consolidating prior plan-staleness briefs from 6.1, 6.4, 6.6, 6.7:

**Actual M6 outcome differs in three respects:**
1. **Tool count** — plan §6.8 anticipated 6; M6 ships 9 native tools (3 added during M6.6 trifecta). Recon (Subfinder + httpx) discovered to be architecturally distinct (ADR-022) and not ToolRunners — no count delta there.
2. **Recon non-registration** — plan §6.8 implies all M6 tools register; ADR-022 (introduced at M6.3) splits recon into a separate helper class with no Registry entry.
3. **Per-tool config shapes** — plan §6.8 didn't anticipate that some tools need additional runtime config beyond `BinaryPath` (Nuclei needs `TemplatesDir` + `DefaultRPS`); `buildRegistry` handles per-tool shape inline.

**Resolution.** Implementation followed the M6-derived shape (9 tools registered + recon helper not registered + per-tool config shapes inline) rather than the literal plan text. Plan §6.8 is a planning artifact, superseded by ADR-022 + the M6 task close-out commits.

### 2026-05-03 — Task 6.8: Recon non-registration code comment (canonical text)

**Pin.** `cmd/worker/registry_wiring.go` `buildRegistry` docstring carries the canonical recon non-registration comment so future engineers reading the registration code see the explanation immediately:

> Recon helpers (Subfinder + httpx) are intentionally NOT registered here per ADR-022: they're pre-scan helpers (target discovery), not ToolRunners (their output is target-discovery data, not events.RawFinding). M8 (Recon-First Pipeline) imports internal/tools/recon and invokes recon.RunRecon directly as a pre-scan phase before per-target scan jobs are dispatched here.

Comment placement adjacent to the spec table (the "registered tools" listing) ensures it cannot drift during refactoring without an obvious diff. `cmd/worker/run.go` carries a shorter cross-reference at the `buildRegistry` call site pointing here.

### 2026-05-03 — Task 6.8: 9 ToolRunners registered + 1 recon helper not registered

**Pin.** Final M6 registration manifest (alphabetical engine name → category → constructor):

| Engine | Category | Constructor |
|---|---|---|
| `checkov` | `iac` | `checkov.NewCheckovRunner` |
| `corstest` | `api` | `corstest.NewCORStestRunner` |
| `depcheck` | `sca` | `depcheck.NewDepCheckRunner` |
| `gitleaks` | `secrets` | `gitleaks.NewGitleaksRunner` |
| `nikto` | `dast` | `nikto.NewNiktoRunner` |
| `nuclei` | `dast` | `nuclei.NewNucleiRunner` |
| `semgrep` | `sast` | `semgrep.NewSemgrepRunner` |
| `sslyze` | `ssl` | `sslyze.NewSSLyzeRunner` |
| `wapiti` | `dast` | `wapiti.NewWapitiRunner` |

**Helper not registered:** `internal/tools/recon` (Subfinder + httpx) per ADR-022.

**Category coverage:** 8 distinct categories (`api, dast, iac, sast, sca, secrets, ssl` + recon-via-helper). DAST has 3 tools (Nuclei + Nikto + Wapiti) — the only multi-tool category at M6 close. Trigger to add a 9th category: M7 container scanners (Trivy → `container`).

**Spec-table single source of truth.** `buildRegistry`'s inline `[]spec` literal drives both registration AND the `[]NativeBinary` list passed to Phase 1. `TestBuildRegistry_NativeBinariesMatchEngines` asserts the bijection so any future drift between the two lists trips a test.

### 2026-05-03 — Task 6.8: Empty-registry warning clearance (5.6 forward-pin closed)

**Pin.** `internal/worker/startup.go` lines 109-115 emit a WARN when `len(registry.Engines()) == 0` ("worker started with empty registry; no jobs will be processed…"). At 5.6 this warning fired on every worker start — explicit forward-pin to M6.

Post-6.8: warning MUST NOT fire under normal operation. Verified two ways:
1. **Automated** — `TestRunMain_NoEmptyRegistryWarning` captures worker log output via a `syncWriter`-wrapped `strings.Builder`; asserts the WARN substring is absent AND the alternative `Info`-with-`registered_engines` path fires.
2. **Smoke-equivalent** — the same fixture used by other `runMain` tests (`runMainFixture` + `installMockBinaries`) sets up 9 mock binaries via `t.Setenv`, so any real-binary smoke test would be redundant with the automated check.

**Sub-note: two distinct failure modes at different layers** (per Watch item D):
- `resolveBinary` (`cmd/worker/binary_resolution.go`) — **fail-fast at startup** when binary path cannot be derived (env unset AND not on `$PATH`). Returns error → `runMain` exits 1.
- Phase 1 stat-check (`internal/worker/startup.go::checkNativeBinaries`) — **fail-soft at runtime** when path was derived but file is missing/non-executable. Logs WARN, continues. Different failure mode from `resolveBinary` because the binary could be present at resolve time and removed later (live system).

Future engineers should not conflate the two.

### 2026-05-03 — Task 6.8: SPEC §7.3 schema-extension trigger fire status + deferral

**Pin.** Schema-reduction trigger (RawFinding fields populated by parsers but not yet in SPEC §7.3) is at **8/9 tools = 89%** post-M6 close — well over the 50% trigger threshold informally agreed at M6.5.

**Reductions inventory** (per-tool field-pop summary, accumulated across M6.5/6.6/6.7 DRIFT entries):
- 8 tools populate fields beyond SPEC §7.3's literal listing (CipherSuite/CertSubject from SSLyze, level-int-derived severity from Wapiti, OWASP-Top-10 tags from Wapiti, etc.)
- 1 tool (Nikto) is uniformly within current SPEC shape

**Deferred per H.A** to a separate M6-close-followup task — keeps 6.8 focused on the wiring assembly. Followup task scope:
1. Audit field-population matrix across all 9 tools (DRIFT entries already provide draft material)
2. Propose specific SPEC §7.3 additions (or argue for keeping fields engine-side, with rationale)
3. Cross-repo verification: Python `RawFinding` schema acceptance of new fields
4. Single docs commit (cross-repo) once Python side confirms shape

**Lean.** Shape additions (additive); no breaking changes anticipated. Python side already accepts unknown JSON fields per ADR-017 inline-findings shape; new fields are zero-cost on Python side until consumed.

### 2026-05-03 — Task 6.8: Pattern 2 env-var-binary at wiring tier (12 cumulative instances)

**Pin (track-only).** SHIELDSCAN_<TOOL>_BINARY env-var-binary pattern (DEVELOPMENT-PATTERNS Pattern 2; promoted at 6.5) reaches 12 cumulative call sites at M6 close:

| # | Layer | Instance | Resolved by |
|---|---|---|---|
| 1-9 | Tool packages | Each `Config.BinaryPath` doc reference | `buildRegistry` (cmd/worker) |
| 10-11 | Recon helpers | Subfinder + httpx | `internal/tools/recon/recon.go::resolveBinary` |
| 12 | Wiring (templates sibling) | `SHIELDSCAN_NUCLEI_TEMPLATES` | `buildRegistry` direct |

Pattern continues to reinforce; nothing new architecturally. Track for sanity-check during M7 Docker service wiring (Pattern 2 doesn't apply to Docker — they use service URLs, not binaries; expect a sibling pattern to emerge).

### 2026-05-03 — Task 6.8: resolveBinary 2nd instance (different layers; 3rd-instance promotion trigger preserved)

**Pin (track-only).** `resolveBinary(envVar, toolName) (string, error)` now has 2 implementations:

| # | Path | Scope | Decision |
|---|---|---|---|
| 1 | `internal/tools/recon/recon.go::resolveBinary` | package-private to `recon` | Lives where consumed (recon helpers self-resolve) |
| 2 | `cmd/worker/binary_resolution.go::resolveBinary` | package-private to `main` | Lives at the wiring-assembly tier |

**Explicit non-promotion at 2 instances** per H.E from M6.8 scope: the two helpers sit at **different architectural layers** (leaf tool package vs binary-assembly tier). Promotion to a shared `internal/binresolve` package would be premature abstraction — the two callers don't share lifecycle, dependency graph, or evolution pressure.

**Promotion triggers preserved** for the future:
- 3rd different-layer instance OR
- 3rd wiring-tier instance

If either fires, extract to `internal/binresolve` (or similar) and consolidate. Until then, the 2-instance state at different layers is the correct architectural placement.

### 2026-05-02 — Task 6.6: Nikto + Wapiti + CORStest runners + Pattern 4 promotion + 2 new parser shapes

**Files shipped (single atomic engine commit):**
- NEW `internal/tools/nikto/{nikto,parse}.go` + `nikto_test.go` + 4 testdata + README
- NEW `internal/tools/wapiti/{wapiti,parse,severity}.go` + `wapiti_test.go` + 4 testdata + README
- NEW `internal/tools/corstest/{corstest,parse,ansi}.go` + `corstest_test.go` + 4 testdata + README
- UPDATE `DEVELOPMENT-PATTERNS.md` (Pattern 4 added: Constants-only field mapping)

**Companion docs commit (`shieldscan-docs/`)** lands 3 TOOL-ARCH surgical patches.

**38 net-new tests at 6.6 close** (12 Nikto + 14 Wapiti + 12 CORStest). Engine total: **292 tests** across 17 packages. Race-clean (concurrent OutputFile test from 6.7 still passes with Wapiti as 2nd consumer), vet-clean, golangci-lint v2 reports 0 issues.

**Three-tool atomic commit** (Nikto first → Wapiti second → CORStest third within commit prep). Sequential implementation per Watch item D; framework regression check after Nikto + Wapiti landed (5 framework tests + Dep-Check 1st-consumer + Wapiti 2nd-consumer all green).

**Pattern promotion at 6.6 (1 fired):**
- **Constants-only field mapping → DEVELOPMENT-PATTERNS.md Pattern 4** (4 instances; promotion threshold met cleanly).

**Pattern advances (track only):**
- **Naturally-clean exit:** 3 → 6 (Nikto + Wapiti + CORStest add). Promotion DEFERRED per H.NEW.8 (wait for unified entry when other exit-code patterns mature).
- **Domain-rules severity mapping:** 1 → 2 (Wapiti `level` integer → canonical). Track for 3rd-instance.
- **OutputFile mode (ADR-023):** 1 → 2 (Wapiti is 2nd consumer; bug workaround for `-o /dev/stdout` corruption). Track.

**Pattern stays at 1 instance (track only):**
- **Plugin-rules parser:** Wapiti's category-keyed iteration is structurally distinct from SSLyze's per-plugin diagnostic shape — see entry 6 below for explicit distinction.

**Two new parser shapes** (1st instance each; track):
- **XML via `encoding/xml`** (Nikto). 4th format observed in M6.
- **Text-with-ANSI** (CORStest). 5th format observed in M6.

**Reductions counter advances 5/6 → 8/9 (83% → 89%).** SPEC §7.3 trigger remains fired; Path A still holds. Comprehensive 9-tool data accumulating for M6-close proposal.

### 2026-05-02 — Task 6.6: Constants-only field mapping → DEVELOPMENT-PATTERNS.md Pattern 4

**Pin (load-bearing).** Three-instance threshold met cleanly + 1 (4 instances at promotion):

| # | Tool | Constants exported |
|---|---|---|
| 1 | M6.5 Gitleaks | `SeverityCritical = "critical"`, `CWEHardcodedCredentials = "CWE-798"` |
| 2 | M6.7 Checkov | `SeverityMedium = "medium"`, `CWEIaCMisconfiguration = "CWE-1032"` |
| 3 | M6.6 Nikto | `SeverityLow = "low"` |
| 4 | M6.6 CORStest | `SeverityMedium = "medium"`, `CWEPermissiveCrossDomain = "CWE-942"` |

**Pattern 4 entry text** (in `DEVELOPMENT-PATTERNS.md`) explicitly distinguishes:
- **When to use:** uniform-severity-by-construction tools without per-rule severity
- **When NOT to use** (anti-instances list): Nuclei/Semgrep/Dep-Check (per-finding mapping), SSLyze/Wapiti (domain-rules tables, separate pattern at 2 instances)
- **Anti-pattern flagged:** scaffolded `mapSeverity()` with no input variation is misleading
- **Cross-pattern reference:** ADR-023's threshold-override at 1 instance vs Pattern 4's clean 3+ instance promotion reflects different cost asymmetries; underlying principle is "pattern velocity should match decision-cost asymmetry"

### 2026-05-02 — Task 6.6: Nikto XML parser (1st instance of encoding/xml)

**Pin.** `internal/tools/nikto/parse.go` uses Go's stdlib `encoding/xml` to parse Nikto's `-Format xml` output. Defines `niktoScan` / `niktoScanDetails` / `niktoItem` structs with XML tags; iterates `<scandetails><item>` elements.

**1st XML parser shape in M6** (4th format after JSONL + single-doc JSON + JSON-array). Track for 3rd-instance promotion. Likely candidate: M7 Trivy (has XML output mode).

**XML stable across Nikto 2.x.** Verified at pre-prep: 2.1.5 + 2.5.0 both emit XML in same shape per Nikto DTD. JSON output added in 2.5+ but 2.1.5 doesn't support; XML chosen for cross-version compatibility.

**Defensive struct design:** optional attrs (`osvdbid`, `targetip`) use `omitempty` so missing fields don't fail unmarshal. Top-level malformed XML IS fatal (consistent with single-doc parser convention from 6.2/6.5/6.7); per-item missing required fields (`id` or empty `description`) skip with WARN.

### 2026-05-02 — Task 6.6: Nikto severity = constant "low" (Pattern 4 application)

**Pin.** `nikto.SeverityLow = "low"`. Every Nikto finding gets the same severity (Pattern 4 constants-only mapping).

**Why "low".** Nikto findings are uniformly **informational web-server misconfigs** (missing security headers, uncommon banners, directory listings, allowed-method enumeration). No CVE-class exploits emitted by default Nikto rules. Industry-standard severity for these is `"low"`.

**CWEID intentionally empty** for Nikto findings. Nikto rules span too many CWE classes (info-disclosure, missing-headers, dangerous-files) for a meaningful constant. Future task or M9 AI pipeline can apply CWE inference if needed.

**Trigger to revisit:** customer asks for finer-grained Nikto severity OR Nikto 3.x adds per-finding severity field.

### 2026-05-02 — Task 6.6: Wapiti OutputFile mode (ADR-023 2nd consumer; bug workaround)

**Pin.** Wapiti uses `NativeRunner.OutputFile = true` with `OutputFilePlaceholder = "{{outputFile}}"` (matches Dep-Check convention from 6.7). **2nd consumer of ADR-023 framework extension.**

**Why required (not chosen):** Wapiti `-o /dev/stdout` corrupts JSON output by injecting the message *"A report has been generated in the file /dev/stdout"* INTO the JSON stream mid-value. Verified empirically at M6.6 pre-prep: `json.load` fails on the resulting bytes. ADR-023 OutputFile mode is the documented workaround.

**Validates ADR-023 abstraction.** First time the framework extension is exercised by a *second consumer* with a *different reason* (Wapiti has a tool bug; Dep-Check has a deliberate file-output design). Confirms the abstraction generalizes beyond Dep-Check's specific case.

**Pattern instance:** OutputFile mode at 2 instances (Dep-Check 6.7 + Wapiti 6.6). Track for 3rd-instance promotion to a possible framework-tier DEVELOPMENT-PATTERN entry. Likely 3rd candidate: M7 Trivy filesystem-scan, or another bug-workaround case.

### 2026-05-02 — Task 6.6: Wapiti -o /dev/stdout corruption bug pinned

**Pin (operational + parser-shape decision).** Verified empirically at M6.6 pre-prep:

```bash
$ wapiti -u https://example.com -m http_headers --flush-session -f json -o /dev/stdout 2>/dev/null > /tmp/clean.json
$ python3 -c "import json; json.load(open('/tmp/clean.json'))"
json.decoder.JSONDecodeError: Expecting value: line 7 column ...
```

The injected message *"A report has been generated in the file /dev/stdout"* lands inside a JSON string value, breaking the parse. Bug appears to be in Wapiti's report-generator: stdout receives both the JSON document AND the success message, written as separate stream operations that interleave at byte boundaries.

**Implication:** Wapiti CANNOT use stdout-mode reliably. ADR-023 OutputFile mode is mandatory.

**Trigger to remove workaround:** upstream Wapiti fix (track via wapiti-scanner GitHub issues). At that point, Wapiti could simplify to stdout-mode like other tools, but the OutputFile mode would still work — no urgency to refactor.

### 2026-05-02 — Task 6.6: Wapiti category-keyed iteration distinct from plugin-rules pattern

**Pin (plugin-rules pattern stays at 1 instance).** Wapiti's `vulnerabilities` map shape:

```json
{
  "vulnerabilities": {
    "Clickjacking Protection": [{vuln_instance}, {vuln_instance}, ...],
    "SQL Injection":          [{...}, ...],
    "Cross Site Scripting":   [{...}, ...]
  }
}
```

Per-instance shape is **uniform across all categories** (`method`, `path`, `info`, `level`, `parameter`, `module`, `http_request`, `curl_command`, `wstg`).

**SSLyze plugin-rules (1st instance, 6.4) is structurally different:**
- SSLyze plugins have heterogeneous per-plugin result shapes (heartbleed has `is_vulnerable_to_heartbleed` boolean; certificate_info has `certificate_deployments` array; tls_X_cipher_suites has `accepted_cipher_suites` array; etc.)
- Each plugin needs domain-specific interpretation rule (`ruleHeartbleed`, `ruleRobot`, etc. dispatched via `pluginRules` table)

**Wapiti is "category-keyed iteration"** (simpler variant): generic iteration over the `vulnerabilities` map; uniform per-instance extraction. No `pluginRules` table; no per-class rule functions.

**Plugin-rules pattern stays at 1 instance (SSLyze only).** Wapiti does NOT advance the count. Pattern remains "track only" at 1 instance. Likely future plugin-rules candidate: M7 tool with heterogeneous per-plugin diagnostics.

**Decision criterion** for future task authors: if all per-class items share the same shape → category-keyed iteration (use Wapiti's `parse.go` as template). If per-class items have heterogeneous shapes → plugin-rules pattern (use SSLyze's `rules.go` as template).

### 2026-05-02 — Task 6.6: Wapiti level integer → canonical (domain-rules 2nd instance)

**Pin.** `internal/tools/wapiti/severity.go` maps Wapiti's `level` integer (1-5) to canonical RawFinding.Severity. Wapiti convention:

| Wapiti `level` | Canonical |
|---|---|
| 1 | info |
| 2 | low |
| 3 | medium |
| 4 | high |
| 5 | critical |

Out-of-range values (0, negative, ≥6) → `"info"` (defensive default; mirrors prior tools).

**Domain-rules severity mapping pattern, 2nd instance after 6.4 SSLyze.** Track for 3rd-instance promotion. Likely candidates: M7 tool with multi-rule severity (Trivy CVSS-derived severity?).

### 2026-05-02 — Task 6.6: CORStest text-with-ANSI parser (1st instance; track for promotion)

**Pin.** `internal/tools/corstest/parse.go` is the **first text-with-ANSI parser shape in M6** (5th format after JSONL + single-doc JSON + JSON-array + XML). Track for 3rd-instance promotion (likely rare; most modern tools emit JSON or XML).

**Architecture:** `bufio.Scanner` line loop; ANSI-strip via regex; multi-line state machine accumulates per-host record fields (Resource / Origin / ACAO / ACAC) until status line emits a finding. Hosts marked "Not vulnerable" are filtered out (no finding emitted).

**Resilience:** orphan status lines (no preceding record fields) are dropped with WARN; records without status lines (interrupted mid-record) are dropped silently when the next separator arrives.

**Future similar-format candidates** (rare): M7-era tools that emit human-readable text for CLI usage. Most modern security tools default to JSON; text parsers are an edge case.

### 2026-05-02 — Task 6.6: CORStest ANSI escape stripping helper

**Pin.** `internal/tools/corstest/ansi.go`: `ansiRE = regexp.MustCompile(\x1b\[[0-9;]*m)` matches CSI SGR escape codes; `stripANSI(s)` replaces all matches with empty string.

**Coverage:** SGR family only (most common in CLI tool color output: foreground/background colors, bold, reset). Other CSI families (cursor movement `H`/`J`/`K`, OSC sequences) use different terminators; CORStest doesn't emit them in normal scan output.

**Trigger to extend:** customer report of non-SGR escape sequences leaking into finding fields. At that point, generalize regex to `\x1b\[[0-9;]*[a-zA-Z]` (all CSI families).

### 2026-05-02 — Task 6.6: CORStest severity = constant "medium" (Pattern 4 application)

**Pin.** `corstest.SeverityMedium = "medium"` + `corstest.CWEPermissiveCrossDomain = "CWE-942"`. Every CORStest finding gets the same severity + CWE (Pattern 4 constants-only mapping).

**Why "medium" + CWE-942.** CORS misconfigurations are industry-standard medium-severity per OWASP API Top 10 + OWASP A01:2021 (Broken Access Control). Wildcard-with-credentials is the most common CORStest finding shape; null-origin and origin-reflection are sub-classes; all fall in the medium-severity band per OWASP. CWE-942 (Permissive Cross-domain Policy with Untrusted Domains) is the umbrella CWE.

**Trigger to revisit:** customer asks for per-CORS-class severity (wildcard-with-credentials → high; null-origin → medium; reflected-origin → low). At that point, replace constant with mapping function driven by description text.

### 2026-05-02 — Task 6.6: CORStest inline-tempfile workaround (NOT canonical for input files)

**Pin (architectural acknowledgment).** CORStest takes a positional URL-list **file**, not a `-u <url>` flag. M6.6 implementation per H.3 Option (a): BuildArgs creates a per-Run tempfile via `os.CreateTemp`, writes `target.URL` to it, passes path as positional arg.

**This pattern is NOT canonical for input-file tools.** Future input-file tools should propose a framework extension (InputFile mode similar to ADR-023 OutputFile) at 3rd instance per asymmetric-cost reasoning.

**At M6.6:** 1st instance only; ad-hoc workaround acceptable per asymmetric-cost analysis (the alternatives at 1 instance — framework extension upfront, closure-shared state — have higher cost than the workaround's ugliness).

**Cleanup limitation acknowledged:** the tempfile is created in `buildArgs` but no defer hook in BuildArgs surface. ParseOutput cannot reliably reach the path created here. **Cleanup is OS-level /tmp reaping (best-effort).** Acceptable for small URL files (~few hundred bytes typically); each Run leaks one small tempfile until the OS cleanup cycle.

**Trigger to formalize InputFile framework extension:** 3rd instance of input-file-needing tool (analogous to ADR-023 promotion at 1st but with stronger asymmetry). At that point, extend NativeRunner with `InputFile bool` + `InputFilePlaceholder string` + `BuildInputContent func(target, cfg) []byte` fields; lifecycle mirrors OutputFile (create → substitute → invoke → defer cleanup).

### 2026-05-02 — Task 6.6: Naturally-clean exit at 6 instances; promotion deferred per H.NEW.8

**Pin (deferral reasoning explicitly documented).** Naturally-clean exit pattern instances post-6.6:

1. M6.1 Nuclei
2. M6.4 SSLyze
3. M6.7 Dep-Check
4. M6.6 Nikto
5. M6.6 Wapiti
6. M6.6 CORStest

**6 instances; threshold-met-3-times-over.** Per H.NEW.8 approval, promotion to DEVELOPMENT-PATTERNS.md continues to be deferred.

**Reasoning** (preserved for future engineers wondering "why isn't naturally-clean promoted at 6 instances?"):

The three exit-code-handling patterns (naturally-clean / runner-tolerates / configuration-not-leniency) form a **coherent vocabulary** documented in 6.5 DRIFT-LOG entry 5 with a decision tree. Promoting just naturally-clean would fragment the conceptual unit:
- "Why is naturally-clean a Pattern but the others aren't?"
- "Where do I find the decision tree?"
- Future readers would need to assemble the full picture from DRIFT-LOG + DEVELOPMENT-PATTERNS, defeating the documentation goal.

**Trigger remains concrete:** configuration-not-leniency (currently 2: Gitleaks + Checkov) OR runner-tolerates (currently 1: Semgrep) hits 3rd instance. Then promote all three together as a unified "Exit-code handling vocabulary" Pattern. Likely fires at 6.3 or M7.

**Asymmetric-cost accepted:** preserving conceptual unity outweighs the documentation lag for naturally-clean alone. This is the inverse of ADR-023's threshold override (where unity *justified* premature promotion); same principle, different direction.

### 2026-05-02 — Task 6.6: reductions counter update (8/9 = 89%; Path A holds)

**Pin.** Counter advances:

| Tool | Reductions |
|---|---|
| 6.1 Nuclei | 3 |
| 6.2 Semgrep | 0 |
| 6.5 Gitleaks | 5 |
| 6.4 SSLyze | 5 |
| 6.7 Dep-Check | 5 |
| 6.7 Checkov | 6 |
| **6.6 Nikto** | **3** (osvdbid + osvdblink, namelink, iplink) |
| **6.6 Wapiti** | **5** (curl_command, referer-when-empty, wstg refs, classifications metadata fold, http_request truncation) |
| **6.6 CORStest** | **2** (Resource/Origin folded, ACAO/ACAC folded) |

**8 of 9 M6 tools have reductions (89%, up from 83%).** SPEC §7.3 trigger remains fired; **Path A still holds** (M6 close timing for proposal). Comprehensive 9-tool data now accumulating; M6-close proposal will have empirically-grounded extension recommendations.

**No new field-types missing per pre-prep field-map analysis.** All Nikto + Wapiti + CORStest reductions are similar shapes to existing tools.

### 2026-05-02 — Task 6.6: Plan §6.6 thinness divergence

**Pin.** Plan §6.6 (`shieldscan-docs/IMPLEMENTATION-PLAN.md` lines 1898+): one sentence × 3 tools.

**Divergence (matches 6.7's "largest at any task" status):** 1 sentence × 3 tools → 38 tests + 2 new parser shapes + Pattern 4 promotion + 3 TOOL-ARCH patches. ~25 LoC plan literal → ~750 LoC src + ~700 LoC tests + ~80 LoC DEVELOPMENT-PATTERNS Pattern 4 entry.

Plan §6.6 was written before M5 chassis + jsonx (6.5) + ADR-023 (6.7) + Pattern 3 (6.7) + reductions counter framework existed.

### 2026-05-02 — Task 6.6: TOOL-ARCH three surgical patches

**Pin.** Companion `shieldscan-docs/` commit lands 3 TOOL-ARCH invocation literal patches:

1. **§6.7 Nikto:** `nikto -h <target> -nointeractive -Format txt -ask no` → `nikto -h <target> -Format xml -ask no -nointeractive` (XML chosen for parser stability; `-Format txt` deprecated parser shape).
2. **§6.8 Wapiti:** `-o /dev/stdout` → `-o {{outputFile}}` (Wapiti bug corrupts /dev/stdout output; ADR-023 OutputFile mode required).
3. **§6.9 CORStest:** `corstest -u https://api.target.com` → `python3 corstest.py <urlfile>` (CORStest takes positional file, not `-u` flag).

All three regression-guarded engine-side: `TestBuildArgs_NoTextFormat` (Nikto), `TestBuildArgs_NoStdoutOutput` (Wapiti), `TestBuildArgs_NoUFlag` (CORStest).

### 2026-05-02 — Task 6.6: Nikto version drift (apt 2.1.5 vs pinned 2.5.0)

**Pin (operational).** VERSIONS.md pins Nikto 2.5.0; Ubuntu apt only ships 2.1.5. Verified at pre-prep: `nikto -Version` → 2.1.5.

**Decision: accept apt's 2.1.5 for M6.6.** XML parser is stable across Nikto 2.x; the version drift doesn't affect parser correctness. Production deploys can choose: (a) accept apt's 2.1.5 + update VERSIONS.md to match, or (b) install Nikto 2.5.0 from source. **OPS milestone (M11) decision.**

**Cross-version risk:** Nikto 2.5.0 may emit slightly different XML attributes. Defensive struct design (omitempty on optional attrs) handles minor variations. Trigger to re-test: 2.5.0 source-install lands at OPS milestone.

### 2026-05-02 — Task 6.6: CORStest commit-SHA pinning (OPS provision-worker.sh note)

**Pin (operational).** VERSIONS.md says "Pin to specific commit SHA" but no SHA listed. M6.6 pre-prep used `git clone --depth 1` (HEAD).

**OPS milestone (M11) action items:**
- Pick a specific SHA from the CORStest GitHub repo (last reasonable commit on `main`)
- Update VERSIONS.md with the SHA
- `provision-worker.sh` clones at that SHA
- Wrapper script at `/usr/local/bin/corstest` invokes `python3 /opt/CORStest/corstest.py "$@"`

**Trigger to revisit:** CORStest releases a tagged version with semver (unlikely; small research tool).

### 2026-05-02 — Task 6.6: PYTHONWARNINGS Pattern 3 reaches 4-5 instances (no new promotion)

**Pin.** Pattern 3 (PYTHONWARNINGS=ignore Env) instances after M6.6:

1. M6.2 Semgrep (1st — observed warning suppression)
2. M6.4 SSLyze (2nd — defense-in-depth)
3. M6.7 Checkov (3rd — defense-in-depth; Pattern 3 promoted)
4. M6.6 Wapiti (4th — defense-in-depth; pipx-installed)
5. M6.6 CORStest (5th — defense-in-depth; Python script via `python3 corstest.py`)

**5 instances; no new promotion needed** (Pattern 3 already promoted at 6.7). Reinforces the pattern's applicability across Python-tool variations (pipx-installed + script-based + research-tool).

### 2026-05-02 — Task 6.6: Three-tool atomic commit shape

**Pin.** Per H.12 + Watch item D: single atomic engine commit covers all 3 tools + Pattern 4 promotion + 18 DRIFT entries. Sequential implementation within commit prep:

1. **Nikto first** (XML novelty) → 12 tests green
2. **Wapiti second** (ADR-023 2nd consumer; framework regression check after Wapiti lands — all framework + Dep-Check + Wapiti tests green)
3. **CORStest third** (text-with-ANSI parser is novel; care for state machine)

**Atomic-commit invariants honored:**
- DEVELOPMENT-PATTERNS.md Pattern 4 exists ⇔ all 4 instances exist
- ADR-023 has 2 consumers ⇔ both Dep-Check + Wapiti compile + tests pass
- 3 TOOL-ARCH patches land in companion docs commit IMMEDIATELY before engine commit

---

### 2026-05-03 — Task 6.3: Subfinder + httpx recon helpers (ADR-022)

**Files shipped (single atomic engine commit):**
- NEW `internal/tools/recon/recon.go` (RunRecon orchestrator + ReconResult + LiveHost + publishIfNotNil + resolveBinary)
- NEW `internal/tools/recon/subfinder.go` (runSubfinder + parseSubfinderOutput)
- NEW `internal/tools/recon/httpx.go` (runHttpx + parseHttpxOutput; stdin pipe per empirical re-eval)
- NEW `internal/tools/recon/{recon,subfinder,httpx}_test.go` (16 tests with goleak TestMain)
- NEW 8 testdata fixtures + README
- UPDATE `internal/events/events.go` (+EventLivenessProbed, +EventReconCompleted)
- UPDATE `internal/events/events_test.go` (regression-guard new constants)

**Companion docs commit (`shieldscan-docs/`)** lands ADR-022 + 2 TOOL-ARCH patches.

**16 net-new tests at 6.3 close** (5 subfinder + 5 httpx + 6 recon orchestrator). Engine total: **270 tests** across 16 packages. Race-clean, vet-clean, golangci-lint v2 reports 0 issues.

**Architecturally distinct M6 task:** recon does NOT fit ToolRunner contract. ADR-022 codifies the decision; recon ships as helpers in `internal/tools/recon/` (first non-tool-runner package under `internal/tools/`).

### 2026-05-03 — Task 6.3: ADR-022 lands (M6's 2nd ADR after ADR-023)

**Pin (load-bearing).** ADR-022 (recon-as-pre-scan-helpers) lands at `shieldscan-docs/SPECIFICATION.md §13`. Codifies the architectural decision that recon tools (Subfinder + httpx) do NOT fit `tools.ToolRunner` because their output is target-discovery data, not `events.RawFinding`.

**M6's 2nd ADR after ADR-023** (M6.7 NativeRunner OutputFile mode). Both ADRs invoke the same asymmetric-cost meta-principle: architectural commitments are made when the alternative is operationally worse, not when a generic threshold is met.

**Cross-reference between ADRs preserved** in ADR-022's text (per H.NEW.9 refinement). Future ADRs may invoke similar cross-referencing pattern.

### 2026-05-03 — Task 6.3: internal/tools/recon/ package (FIRST non-tool-runner package)

**Pin.** `internal/tools/recon/` is the first package under `internal/tools/` that does NOT contain a ToolRunner factory. Sibling to:
- `internal/tools/jsonx/` (helpers — no NewXRunner)
- Per-tool ToolRunner packages (`nuclei/`, `semgrep/`, `gitleaks/`, etc.) — each with `NewXRunner`

The recon package exports `RunRecon` (orchestrator) + `ReconResult` + `LiveHost` types. No `NewReconRunner` factory; no NativeRunner construction; no Registry registration.

**Layout:**
- `recon.go` — RunRecon orchestrator + types + helpers (publishIfNotNil, resolveBinary)
- `subfinder.go` — runSubfinder + parseSubfinderOutput
- `httpx.go` — runHttpx + parseHttpxOutput

**Per-tool files split** (subfinder.go + httpx.go) for parser-ownership clarity, symmetric with how 6.7 split parse.go from severity.go.

### 2026-05-03 — Task 6.3: RunRecon signature + ReconResult composition + LiveHost 6-field shape

**Pin.** `RunRecon` signature:

```go
func RunRecon(
    ctx context.Context,
    domain string,
    limit int,
    publisher *redis.ProgressPublisher,
    log zerolog.Logger,
) (*ReconResult, error)
```

Two extensions beyond plan §6.3 literal:
1. **Logger arg added** (per scope §16). Plan literal omits but every other 6.x parser takes one — symmetric for fail-soft logging within RunRecon.
2. **`limit <= 0` defensive default → `defaultLimit = 100`** (matches TOOL-ARCH §8.1 max-100-subdomains-per-scan).

**ReconResult shape** matches plan §6.3 literal: `{Subdomains []string, LiveHosts []LiveHost}`.

### 2026-05-03 — Task 6.3: LiveHost extended beyond plan literal (3 → 6 fields per H.NEW.1)

**Pin.** Plan §6.3 LiveHost has 3 fields (`URL, StatusCode, Tech`). 6.3 implementation extends to 6 fields:

| Field | Source (httpx JSONL) |
|---|---|
| `URL` | `url` |
| `StatusCode` | `status_code` |
| `Title` | `title` |
| `Tech` | `tech` |
| `Webserver` | `webserver` |
| `ContentType` | `content_type` |

**Why extend.** httpx emits ~25 fields per host; M8's downstream consumers may benefit from more than just URL/status/tech for target-list construction + tool-selection routing + UI display. The 6-field shape is conservative — it covers M8's likely needs without forcing a future-iteration refactor.

**Trigger to extend further:** M8 implementation surfaces a need for a field currently dropped (e.g., latency, IP for network-policy scoping). Extend additively; existing M8 callers remain compatible.

### 2026-05-03 — Task 6.3: Direct exec.CommandContext (NOT NativeRunner) per H.NEW.5

**Pin.** `runSubfinder` and `runHttpx` invoke `exec.CommandContext` directly. They do NOT use `tools.NativeRunner`.

**Architectural consistency with ADR-022:** NativeRunner enrichment loop (ToolName / EngineCategory / DiscoveredAt / Fingerprint) is irrelevant when the output isn't `[]events.RawFinding`. Forcing the abstraction would add complexity for no value — and would suggest recon belongs in the ToolRunner ecosystem when it explicitly doesn't (per ADR-022).

**Subprocess management uses standard ADR-021 patterns:**
- `context.WithTimeout(ctx, 60s)` for subfinder; `120s` for httpx
- Caller-cancel ctx error takes precedence over subprocess error (`if ctxErr := ctx.Err(); ctxErr != nil` check)
- `exec.CommandContext` ensures ctx cancel SIGKILLs the subprocess

### 2026-05-03 — Task 6.3: httpx input strategy — stdin pipe (empirical re-eval reverses lean)

**Pin.** Per H.NEW.6 lean was inline-tempfile. Empirical re-eval at 6.3 implementation REVERSES the lean: **stdin pipe works cleanly**.

**Empirical verification:**

```bash
{ echo "https://example.com"
  echo "https://www.cloudflare.com"
  echo "https://github.com"
} | httpx -silent -json -status-code -title -tech-detect -web-server
```

→ 3 hosts piped via stdin, 3 valid JSONL records on stdout. No corruption, no mixing issues like Wapiti's `-o /dev/stdout` bug at M6.6.

**Implementation choice:** `cmd.Stdin = strings.NewReader(strings.Join(subdomains, "\n") + "\n")` in `runHttpx`. Cleaner than inline-tempfile (no tempfile lifecycle to manage; no `os.Remove` defer; no error-path leakage).

**Pattern instance count recalibrated:**
- Inline-tempfile workaround: stays at **1 instance** (CORStest at 6.6 only)
- InputFile framework extension trigger: **still 1st-instance need;** unchanged

**Empirical re-eval discipline pattern (track-only):**
- 6.6 Nikto stdout XML (confirmed empirically — clean)
- 6.3 httpx stdin (confirmed empirically — clean; reverses lean)
- 2 instances of "implementation overrides pre-prep lean based on empirical data"; track for 3rd-instance promotion to DEVELOPMENT-PATTERNS

### 2026-05-03 — Task 6.3: Failure-tolerant orchestration (errors NEVER propagate)

**Pin.** Per plan §6.3 literal + scope §E table: subfinder/httpx failures NEVER propagate to RunRecon's caller. Partial data is the useful state for M8's routing decisions.

| Scenario | RunRecon returns |
|---|---|
| Happy (both succeed) | `{Subdomains: [...N], LiveHosts: [...M]}, nil` |
| Subfinder fails | `{}, nil` (empty; no error) |
| httpx fails | `{Subdomains: [...N]}, nil` (subdomains preserved; no error) |
| Both fail | `{}, nil` (empty; no error — subfinder fails first; httpx not invoked) |
| 0 subdomains | `{Subdomains: []}, nil` (httpx skipped) |

**Recon-completed event always fires** with `status` field signaling outcome (`ok` / `subfinder_failed` / `httpx_failed` / `no_subdomains`). M8 can react to status in addition to data presence.

**4 failure-tolerance tests** in `recon_test.go` cover each scenario explicitly.

### 2026-05-03 — Task 6.3: Publisher nil-safety (publishIfNotNil helper)

**Pin.** `RunRecon` accepts `publisher *redis.ProgressPublisher` which MAY be nil. Tiny package-private helper:

```go
func publishIfNotNil(ctx context.Context, publisher *redis.ProgressPublisher, eventType events.EventType, payload events.ProgressEvent) {
    if publisher == nil {
        return
    }
    _, _ = publisher.Publish(ctx, eventType, payload)
}
```

Tests pass `nil` (no Redis client needed for parser tests + orchestrator tests). Production callers always supply a real publisher.

**Publish errors are intentionally swallowed** — recon should not fail because progress publishing failed. Per ADR-021 fail-soft posture; matches 5.6 Heartbeat's WARN-and-continue behavior.

### 2026-05-03 — Task 6.3: Two new event types (EventLivenessProbed + EventReconCompleted)

**Pin.** `internal/events/events.go` adds two `EventType` constants:

```go
EventLivenessProbed EventType = "liveness_probed"  // emitted by recon.RunRecon after httpx phase
EventReconCompleted EventType = "recon_completed"  // emitted by recon.RunRecon at end of pipeline
```

Existing event types reused:
- `EventReconStarted` (defined at 5.1; emitted at RunRecon entry)
- `EventSubdomainsDiscovered` (defined at 5.1; emitted after subfinder)

**4-event recon progress sequence** (in order): `recon_started` → `subdomains_discovered` → `liveness_probed` → `recon_completed`.

**Cross-repo verification completed pre-implementation:** `shieldscan-api/src/app/services/completions_consumer.py:167` uses string-based dispatch with default skip-unknown behavior (`if event.get("event_type") != "job_completed":`). New event types accepted without rejection. **No blocker.**

`internal/events/events_test.go` regression-guard updated to include both new constants in the EventType verification table.

### 2026-05-03 — Task 6.3: TOOL-ARCH §6.3 Subfinder JSONL invocation patch

**Pin.** Companion docs commit updates TOOL-ARCH §6.3 line 545:
- BEFORE: `subfinder -d example.com -silent -o - -max-time 60`
- AFTER: `subfinder -d example.com -oJ -silent -max-time 60`

**Why.** `-o -` produces text output (one hostname per line, no metadata). `-oJ` produces JSONL with `{host, input, source}` per record, more parser-stable across versions and surfaces the source field for operational diagnostics (debugging which intel source contributed which subdomain).

### 2026-05-03 — Task 6.3: TOOL-ARCH §6.4 httpx flag-list extension patch

**Pin.** Companion docs commit updates TOOL-ARCH §6.4 line 574 invocation:
- BEFORE: `httpx -silent -json -status-code -tech-detect`
- AFTER: `httpx -silent -json -status-code -title -tech-detect -web-server`

**Why.** Adds `-title` and `-web-server` flags to populate `LiveHost.Title` and `LiveHost.Webserver` (per H.NEW.1 6-field LiveHost extension). Without these flags, httpx omits the corresponding fields from output, leaving 2 of 6 LiveHost fields empty.

### 2026-05-03 — Task 6.3: 6.8 forward-pin (non-registration code comment)

**Pin (forward-look).** When 6.8 wiring lands, `cmd/worker/run.go` will populate `worker.NewRegistry` with the 9 ToolRunners (Nuclei + Semgrep + Gitleaks + SSLyze + Dep-Check + Checkov + Nikto + Wapiti + CORStest). Subfinder and httpx will be ABSENT.

**Required code comment text** (per H.11 refinement):

```go
// Note: Subfinder and httpx are NOT registered with the Registry.
// Per ADR-022 (M6.3), they are pre-scan helpers (recon.RunRecon)
// invoked by M8's Recon-First Pipeline before per-target scan jobs
// are dispatched. They produce target-discovery data
// (recon.ReconResult), not events.RawFinding, so the ToolRunner
// contract doesn't apply.
//
// If you're adding a new tool: check whether your tool produces
// events.RawFinding (vulnerability findings) or some other shape
// (target lists, wordlists, configuration data, etc.). If
// findings → register here. If non-finding output → ship as a
// helper package under internal/tools/<name>/ following the
// recon precedent + ADR-022.
```

DRIFT entry pinned so 6.8's author finds the canonical text and includes it verbatim.

### 2026-05-03 — Task 6.3: Subfinder passive-only default (no -all flag)

**Pin.** `runSubfinder` deliberately omits the `-all` flag. Conservative default — `-all` enables active enumeration across all sources (including ones that may flag aggressive enumeration as DoS).

**Trigger to revisit:** customer demand for active enumeration OR M9 AI pipeline value-add from the additional discovery data. At that point, add a `ScanConfig.SubfinderActive bool` opt-in.

### 2026-05-03 — Task 6.3: ProjectDiscovery tool family consistency

**Pin (positive signal).** Subfinder + httpx are the same tool family as Nuclei (M6.1). All three:
- Install via `go install github.com/projectdiscovery/<tool>@<version>` (no apt package; no pipx)
- Path: `~/go/bin/<tool>` (Go install convention)
- CLI patterns: `-silent` to suppress banner; JSONL output via `-j` / `-oJ` / `-json`
- Naturally-clean exit codes (no flag needed)

**Pattern instance count update (positive):** PYTHONWARNINGS=ignore Env pattern does NOT apply (Go binaries, not Python tools). Env=nil for both Subfinder + httpx in their direct exec.CommandContext invocation paths. SHIELDSCAN_<TOOL>_BINARY pattern (DEVELOPMENT-PATTERNS Pattern 2): 11th + 12th instances — reinforces Pattern 2 without triggering anything new.

### 2026-05-03 — Task 6.3: Plan §6.3 thinness divergence + LiveHost extension rationale

**Pin.** Plan §6.3 (lines 1817-1869) is substantively closer to scope intent than prior 6.x plan literals — it provides RunRecon signature, ReconResult composition, and a code skeleton. **6.3 is the most plan-faithful task in M6** (smaller divergence than 6.1/6.2/6.5/6.4/6.7/6.6).

Material divergences:
1. **LiveHost extended 3 → 6 fields** (per H.NEW.1; documented entry 4 above). Conservative extension; covers M8's likely needs.
2. **Logger arg added to RunRecon** (per scope §16; documented entry 3 above). Symmetric with all other 6.x parser closures; fail-soft logging discipline.
3. **Defensive `defaultLimit=100`** when `limit <= 0` (matches TOOL-ARCH §8.1).

Otherwise: scope substantially matches plan literal. Honoring the spirit, expanding modestly.

### 2026-05-03 — Task 6.3: pattern landscape impact (recon contributes to ADR-022 only)

**Pin.** Recon doesn't add to most pattern instance counts (recon is helpers, not tools):
- Pattern 1 (Trigger-based deferral): unchanged
- Pattern 2 (`SHIELDSCAN_<TOOL>_BINARY`): 11→12 instances (Subfinder + httpx; reinforces)
- Pattern 3 (`PYTHONWARNINGS=ignore`): unchanged (recon tools are Go binaries; not pipx-Python)
- Pattern 4 (Constants-only field mapping): unchanged (recon doesn't produce findings)
- ADR-023 (NativeRunner OutputFile mode): unchanged (recon uses direct exec; not NativeRunner)
- jsonx helpers: 8→10 instances (Subfinder + httpx parsers use ExtractString / ExtractStringSlice / ExtractFloat)
- Inline-tempfile workaround: stays at 1 (CORStest only — empirical re-eval at httpx reversed to stdin)
- Naturally-clean exit: unchanged at 6 (recon helpers don't strictly use exit-code vocabulary; manage own subprocess)

**ADR-022 is the architectural artifact** that legitimizes the recon-as-helpers commitment. It's documentation tier (cross-repo), not pattern tier (engine-side). DEVELOPMENT-PATTERNS.md unchanged at 6.3.

**New tracked-pattern candidate at 6.3:** "empirical re-eval discipline" (2nd instance — 6.6 Nikto stdout + 6.3 httpx stdin). Both reversed pre-prep leans based on concrete data. Track for 3rd-instance promotion. Future task authors: grep for "empirical re-eval" in DRIFT-LOG.

### 2026-05-03 — Task 6.3: M8 forward-pin (speculative invocation pattern)

**Pin (forward-look).** ADR-022's "Speculative M8 invocation pattern" section warns explicitly that the example call site is best-effort prediction, NOT a binding contract. M8 implementation may refine the API.

**The recon-as-helpers principle holds regardless of how M8's call site evolves.** ReconResult + LiveHost types are stable; how M8 invokes RunRecon (or wraps it in a coordinator type, batches across scan-job batches, applies filtering layers, etc.) is M8's design choice.

**M8's binding contract from M6.3:**
- `recon.ReconResult` shape (Subdomains + LiveHosts)
- `recon.LiveHost` shape (6 fields)
- `recon.RunRecon` signature (ctx, domain, limit, publisher, log → ReconResult, err)
- 4-event progress sequence (recon_started → subdomains_discovered → liveness_probed → recon_completed) with `status` field on terminal event
- Failure-tolerant semantics (errors NEVER propagate; partial data canonical)

---

### 2026-05-02 — Task 6.7: Dep-Check + Checkov runners + NativeRunner OutputFile extension (ADR-023)

**Files shipped (single atomic engine commit):**
- UPDATE `internal/tools/native.go` (NativeRunner: +`OutputFile`, +`OutputFilePlaceholder`, +`ParseOutputFile` fields; bimodal `Run()` with tempfile lifecycle)
- UPDATE `internal/tools/native_test.go` (+5 framework tests for OutputFile mode; +3 imports)
- NEW `internal/tools/depcheck/{depcheck,parse,severity}.go` + `depcheck_test.go` + 4 testdata fixtures + README
- NEW `internal/tools/checkov/{checkov,parse}.go` + `checkov_test.go` + 4 testdata fixtures + README
- UPDATE `DEVELOPMENT-PATTERNS.md` (Pattern 3 added: PYTHONWARNINGS=ignore Env)

**Companion docs commit (`shieldscan-docs/`)** lands ADR-023.

**32 net-new tests at 6.7 close** (5 framework + 12 depcheck + 12 checkov + 3 from Pattern 3 promotion implicit in DefaultsApplied tests). Engine total: **254 tests** across 14 packages. Race-clean (concurrent OutputFile test verified under -race), vet-clean, golangci-lint v2 reports 0 issues.

**Most architecturally significant M6 task to date:** framework extension + two new tool packages + 1 DEVELOPMENT-PATTERNS promotion + 1 ADR.

**Three first-instance pattern advances at 6.7 (track only — no promotions triggered):**
1. **Constants-only field mapping** advances 1 → 2 instances (Gitleaks + Checkov). Track for promotion at 3rd.
2. **Naturally-clean exit** advances 2 → 3 instances (Nuclei + SSLyze + Dep-Check). 3rd-instance threshold reached, but per H.NEW.7 promotion deferred — wait for unified "exit-code handling" entry when configuration-not-leniency or runner-tolerates also hits 3rd instance.
3. **Configuration-not-leniency exit** advances 1 → 2 instances (Gitleaks + Checkov). Track.

**Pattern promotions at 6.7 (1 fired):**
1. **PYTHONWARNINGS=ignore Env → DEVELOPMENT-PATTERNS.md Pattern 3** (3rd-instance threshold met cleanly: Semgrep + SSLyze + Checkov).

**Premature promotion at 6.7 (1 fired; threshold-override):**
2. **NativeRunner OutputFile mode → ADR-023** (1st instance only — Dep-Check). Three-instance threshold OVERRIDDEN per asymmetric-cost reasoning: hack alternatives all rejected as race-prone or architecturally messy.

**Reductions counter advances 3/4 → 5/6 (75% → 83%).** SPEC §7.3 trigger remains fired; Path A still holds (M6 close timing). No new field-types missing per pre-prep field-map analysis — all reductions are similar shapes to existing tools.

### 2026-05-02 — Task 6.7: NativeRunner OutputFile extension (framework change; ADR-023)

**Pin (load-bearing).** `internal/tools/native.go` adds three fields to `NativeRunner`:

```go
OutputFile            bool
OutputFilePlaceholder string
ParseOutputFile       func(outputFilePath string) ([]events.RawFinding, error)
```

`Run()` becomes bimodal:
- **Stdout-mode** (`OutputFile=false`, default): unchanged — subprocess stdout captured, ParseOutput receives bytes.
- **File-output mode** (`OutputFile=true`): `os.CreateTemp` mints a unique tempfile; placeholder substitution into args; subprocess invoked; `ParseOutputFile` receives the path; `defer os.Remove` cleans up regardless of success/error.

**Validation at Run entry**: `OutputFile=true` requires both `ParseOutputFile != nil` AND `OutputFilePlaceholder != ""`. Surfaces as standard error (not panic).

**5 framework tests** (`internal/tools/native_test.go`):
1. `TestNativeRunner_OutputFile_PathSubstituted` — placeholder MUST be replaced before exec
2. `TestNativeRunner_OutputFile_TempfileCleanedUpOnSuccess` — defer cleanup verified
3. `TestNativeRunner_OutputFile_TempfileCleanedUpOnError` — symmetric cleanup on subprocess error
4. `TestNativeRunner_OutputFile_ConcurrentRunsDistinctPaths` — 10 parallel Run() calls, distinct paths under -race
5. `TestNativeRunner_OutputFile_Validation` — table-driven: missing-ParseOutputFile + missing-Placeholder

**Backward-compat verified pre-implementation per Watch item A:** all 4 existing tool packages (nuclei, semgrep, gitleaks, sslyze) test suites passed unchanged after framework extension. Stdout-mode is the zero-value default; existing code paths unaffected.

**Full ADR-023 lands at companion `shieldscan-docs/SPECIFICATION.md §13` commit.**

### 2026-05-02 — Task 6.7: Dep-Check tempfile lifecycle (per-Run unique paths via os.CreateTemp)

**Pin.** Per ADR-023, NativeRunner uses `os.CreateTemp("", "shieldscan-"+ToolName+"-*.out")` to mint a per-Run unique tempfile path. The "*" wildcard is a stdlib convention that gets replaced with a random suffix; the resulting path is guaranteed unique even under concurrent `Run()` calls on the same NativeRunner.

**Tempfile naming:** `shieldscan-<toolname>-<random>.out`. The toolname prefix aids `ls /tmp` debugging. The `.out` suffix is generic (per H.6 lean) — file might contain JSON or XML or other format depending on tool config.

**Cleanup:** `defer os.Remove(tempfilePath)` regardless of subprocess success/error (per H.3 lean). `os.Remove` errors ignored — cleanup is best-effort; the OS will eventually reap stale tempfiles via tmpfs cleanup or similar.

**Verified race-free** by `TestNativeRunner_OutputFile_ConcurrentRunsDistinctPaths` running 10 parallel Run() calls under `-race`; all 10 received distinct tempfile paths.

### 2026-05-02 — Task 6.7: Per-CVE findings convention (1 dep with 5 CVEs → 5 RawFindings)

**Pin.** `internal/tools/depcheck/parse.go` iterates `dependencies[i].vulnerabilities[j]` and emits one RawFinding per CVE. A dep with 5 CVEs produces 5 findings, each with the same `CodeFile` (dep file path) but distinct `FindingType` (CVE id).

**Why per-CVE.** Mirrors industry SCA tooling conventions (Snyk, GitHub Dependabot, Trivy SCA). Per-CVE granularity enables:
- AI pipeline dedup per-CVE (same CVE across tools = same vulnerability).
- Per-CVE remediation tracking (each CVE has its own fix version).
- Per-CVE severity (a dep can have a critical CVE + a low CVE).

**Aggregation alternative rejected.** Per-dep aggregated findings (1 dep with 5 CVEs → 1 finding with CVE list folded) would lose per-CVE severity context and make AI pipeline dedup harder.

**Fingerprint dedup via `tools.ComputeFingerprint`** produces distinct fingerprints (FindingType differs per CVE), so the convention is fingerprint-stable.

### 2026-05-02 — Task 6.7: Dep-Check naturally-clean exit (3rd instance; promotion deferred per H.NEW.7)

**Pin.** Dep-Check 9.2.0 exits 0 by default even when vulnerabilities found. `--failOnCVSS <threshold>` flag would change this — DELIBERATELY OMITTED to keep exit code semantics simple and consistent with naturally-clean pattern.

**Naturally-clean exit pattern instances:**
- 6.1 Nuclei (1st)
- 6.4 SSLyze (2nd)
- **6.7 Dep-Check (3rd)** — 3rd-instance threshold reached

**Promotion to DEVELOPMENT-PATTERNS.md DEFERRED per H.NEW.7.** Reasoning: the three exit-code-handling patterns (naturally-clean / runner-tolerates / configuration-not-leniency) form a coherent vocabulary documented in 6.5 DRIFT-LOG entry 5 with a decision tree. Promoting just naturally-clean would fragment the conceptual unit. Wait for either configuration-not-leniency or runner-tolerates to also hit 3rd instance, then promote all three together as a unified "Exit-code handling vocabulary" pattern.

**Trigger to promote**: configuration-not-leniency advances to 3rd instance (currently 2: Gitleaks + Checkov), OR runner-tolerates advances to 3rd instance (currently 1: Semgrep). Likely fires at 6.6 Wapiti family.

**Regression-guarded by `TestBuildArgs_NoFailOnCVSSFlag`.**

### 2026-05-02 — Task 6.7: Checkov constant Severity = "medium" (constants-only mapping 2nd instance)

**Pin.** OSS Checkov (3.2.340 verified at pre-prep) emits `severity: null` for ALL checks. Severity is a Bridgecrew Cloud commercial feature; OSS edition has no per-check severity field.

**Decision per H.NEW.1:** apply constant `SeverityMedium = "medium"` to every Checkov RawFinding. Industry-standard default for IaC misconfigurations. Downstream AI pipeline can tune via context.

**Constants-only mapping pattern instances:**
- 6.5 Gitleaks (1st: SeverityCritical + CWEHardcodedCredentials)
- **6.7 Checkov (2nd: SeverityMedium + CWEIaCMisconfiguration)**

**Track for 3rd-instance promotion.** Likely candidate: M7 Trivy (similar OSS-tool pattern with limited per-finding metadata).

**Trigger to revisit:** Checkov adds per-check severity to OSS edition (commercial feature drift). At that point, replace constant with mapping function driven by the `severity` field.

### 2026-05-02 — Task 6.7: Checkov constant CWE = "CWE-1032"

**Pin.** Per H.NEW.2, every Checkov finding maps to `CWEIaCMisconfiguration = "CWE-1032"` (OWASP IaC Misconfiguration). OSS Checkov has no per-check CWE field; CWE-1032 is the umbrella IaC-misconfig category covering all Checkov rule classes (S3 misconfig, security-group misconfig, missing-encryption, etc.).

**Per-rule CWE mapping rejected** (Option β in pre-prep): hundreds of Checkov rules; per-rule table would be brittle and incomplete. Constant CWE keeps the parser simple; AI pipeline can refine if needed.

**Trigger to revisit:** customer asks for finer-grained CWE classification; OR Bridgecrew open-sources their per-check CWE table.

### 2026-05-02 — Task 6.7: Checkov --soft-fail (configuration-not-leniency 2nd instance)

**Pin.** Checkov 3.2.340 exits 1 on findings by default. Per H.NEW.4, BuildArgs includes `--soft-fail` flag forcing exit 0; NativeRunner's `ExitCodeLenient` stays `false`. Configuration-not-leniency pattern.

**Configuration-not-leniency instances:**
- 6.5 Gitleaks (1st: `--exit-code=0`)
- **6.7 Checkov (2nd: `--soft-fail`)**

**Track for 3rd-instance promotion** (currently 1 from threshold). Pattern would promote alongside the unified exit-code-handling DEVELOPMENT-PATTERNS entry deferred at H.NEW.7.

**Regression-guarded by `TestBuildArgs_SoftFailPresent`.**

### 2026-05-02 — Task 6.7: Checkov code_block 2-D array → flattened CodeSnippet

**Pin.** Checkov `code_block` is a 2-D structure: `[[lineNumber, codeText], ...]`. The `flattenCodeBlock` helper in `internal/tools/checkov/parse.go` converts it to a single source string preserving line content (line numbers dropped — they're already encoded in `file_line_range`):

```
in:  [[5, "resource X {\n"], [6, "  attr = ...\n"]]
out: "resource X {\n  attr = ...\n"
```

Truncated to 2 KiB via `jsonx.Truncate` consistent with 6.2/6.4/6.5 conventions.

**Per-pair malformed entries skipped silently** (e.g., single-element pairs, wrong-type entries). Tested via `TestFlattenCodeBlock` table-driven cases.

**Reduction acknowledged:** the 2-D structure (with line-number-per-line tracking) is reduced to flat source. Reductions counter entry 10.

### 2026-05-02 — Task 6.7: PYTHONWARNINGS Pattern 3 promotion to DEVELOPMENT-PATTERNS.md

**Pin.** Three-instance threshold met cleanly (Semgrep + SSLyze + Checkov). `Env: []string{"PYTHONWARNINGS=ignore"}` for every pipx-installed Python tool runner regardless of currently-observed warnings.

DEVELOPMENT-PATTERNS.md Pattern 3 entry text drafted at H.10; lands at the engine commit. References:
- All three instances (semgrep.go / sslyze.go / checkov.go)
- Cross-link to ADR-023 (asymmetric-cost reasoning, since this pattern's "defense-in-depth despite no warnings observed" mirrors ADR-023's threshold-override reasoning)
- "When NOT to use" guidance (Go binaries, JVM tools, native binaries)

### 2026-05-02 — Task 6.7: reductions counter update (5/6 tools = 83%; Path A holds)

**Pin.** Counter advances:

| Tool | Reductions |
|---|---|
| 6.1 Nuclei | 3 |
| 6.2 Semgrep | 0 |
| 6.5 Gitleaks | 5 |
| 6.4 SSLyze | 5 |
| **6.7 Dep-Check** | **5** (references[], vulnerableSoftware[], hashes md5/sha1/sha256, evidenceCollected, multi-CWE beyond [0]) |
| **6.7 Checkov** | **6** (bc_check_id, guideline, evaluations, caller_file_*, entity_tags, code_block 2-D structure folded) |

**5 of 6 M6 tools have reductions (83%, up from 75%).** SPEC §7.3 trigger remains fired; **Path A still holds** (M6 close timing for proposal).

**No new field-types missing.** All Dep-Check + Checkov reductions are similar shapes to existing tools. Maybe candidates if M6 close proposal goes ahead: `References []string` (cross-tool consistent), but that's been deferred since 6.1 too.

### 2026-05-02 — Task 6.7: Plan §6.7 thinness divergence (largest at any M6 task)

**Pin.** Plan §6.7 (`shieldscan-docs/IMPLEMENTATION-PLAN.md` lines 1910+): one sentence × 2 tools.

**Divergence (largest at any M6 task; exceeds 6.4):**
- 1 sentence × 2 tools → 32 tests + framework extension + 1 ADR + 1 DEVELOPMENT-PATTERNS promotion
- ~25 LoC plan literal → ~700 LoC src + ~600 LoC tests + ~70 LoC framework extension + 1 ADR

Plan §6.7 was written before M5 chassis + ADR-023 + pattern-promotion infrastructure existed. No surgical doc patches needed at 6.7 (TOOL-ARCH §6.10 + §6.11 invocation literals validated at pre-prep).

### 2026-05-02 — Task 6.7: Dep-Check Java JRE dependency (OPS provision-worker.sh note)

**Pin (operational).** Dep-Check is a JVM-based tool. M6.7 pre-prep verified: fresh Ubuntu 24.04 install requires `apt install default-jre` (or pinned OpenJDK 21) before Dep-Check can start. Without Java, `dependency-check.sh --version` fails with `Error: JAVA_HOME is not defined correctly`.

**OPS milestone (M11) `provision-worker.sh` action items:**

```bash
# Install JDK before Dep-Check unzip:
apt install -y default-jre

# Verify:
java --version  # expect openjdk 21.x.x

# Then unzip Dep-Check 9.2.0 release archive:
curl -sL -o dependency-check.zip \
    "https://github.com/jeremylong/DependencyCheck/releases/download/v9.2.0/dependency-check-9.2.0-release.zip"
unzip dependency-check.zip -d /opt/
ln -sf /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check.sh
```

**SHIELDSCAN_DEPCHECK_BINARY env** points to `dependency-check.sh` (per M6.7 Watch item A — single env var; `_HOME`-based variant rejected as needlessly complex).

### 2026-05-02 — Task 6.7: Dep-Check NVD API key requirement (OPS milestone configuration)

**Pin (operational + commit-blocker for actual scans).** NVD CVE database requires an API key as of 2026 — the unauthenticated endpoint returns 403/404. Verified empirically at M6.7 pre-prep: `dependency-check.sh --updateonly` failed with `[ERROR] Error updating the NVD Data; the NVD returned a 403 or 404 error`.

**M6.7 implementation impact:** parser tests use synthesized fixtures (per documented schema); no real scan performed. Production deploys MUST configure the key.

**OPS milestone (M11) `provision-worker.sh` action items:**

```bash
# Set DEPCHECK_NVD_API_KEY env var (or pass --nvdApiKey via NativeRunner.Env)
# Get a key from: https://nvd.nist.gov/developers/request-an-api-key
export DEPCHECK_NVD_API_KEY="<key>"

# First-run NVD update (takes 15-30 min):
dependency-check.sh --updateonly --nvdApiKey "$DEPCHECK_NVD_API_KEY"
```

**Trigger to revisit:** NVD changes their API access model (likely won't; rate limits will get tighter, not looser).

### 2026-05-02 — Task 6.7: Two-tool atomic commit shape (single commit covers both + framework)

**Pin.** Per H.NEW.8 + Watch item D: single atomic engine commit covers Dep-Check + Checkov + framework extension + DEVELOPMENT-PATTERNS update + 16 DRIFT entries. Sequential implementation within commit prep (Dep-Check + framework first; Checkov second per Watch item E) but landed atomically.

**Atomic-commit invariants honored:**
- NativeRunner OutputFile mode exists ⇔ Dep-Check uses it
- DEVELOPMENT-PATTERNS Pattern 3 exists ⇔ 3rd instance (Checkov) exists
- ADR-023 lands in companion docs commit (separate repo) immediately before engine commit

### 2026-05-02 — Task 6.7: ADR-023 acknowledgment

**Pin.** ADR-023 lands in `shieldscan-docs/SPECIFICATION.md §13` (companion docs commit `docs(spec): add ADR-023 NativeRunner file-output mode (M6.7)`).

**ADR-023 in brief**: NativeRunner gains `OutputFile` mode for tools that write findings to file rather than stdout. Three-instance threshold OVERRIDDEN per asymmetric-cost reasoning (hack alternatives all rejected as race-prone). Triggers to revisit: 5+ tools using OutputFile mode (consider separate FileOutputRunner type), tools that write to stderr (distinct shape), >5% performance regression from tempfile I/O, operator concern about tempfile location.

**Cross-references:** DEVELOPMENT-PATTERNS.md preamble explains the asymmetric-cost reasoning generally; ADR-023 is the load-bearing instance. Pattern 3 (PYTHONWARNINGS) entry references ADR-023 for the reasoning analogy.

### 2026-05-02 — Task 6.7: jsonx-extension trigger watch update (still 1st-instance need post-6.7)

**Pin (forward-look update).** The jsonx-extension trigger watch from 6.4 entry 14 (path-walker `ExtractStringPath`, `ExtractBool`) — Dep-Check's parser uses shallow access (`vulnerabilities[i].name`, `vulnerabilities[i].cvssv3.baseScore`); 1-2 levels deep, manageable via existing `jsonx.ExtractMap` chains. Checkov similarly shallow.

**Path-walker need does NOT deepen at 6.7.** Still 1st-instance need (from SSLyze rules at 6.4). Likely 2nd instance: M6.6 Wapiti or M7.x tools with deeper nesting. No promotion at 6.7.

**`boolFrom` helper from 6.4 (in `internal/tools/sslyze/rules.go`):** still 1st instance. Neither 6.7 tool needs lenient bool extraction (Dep-Check uses string severity; Checkov has no bool fields parser uses). No promotion.

---

### 2026-05-02 — Task 6.4: SSLyze native runner + plugin-rules parser + first-time CipherSuite/CertSubject

**Files shipped (single engine commit):**
- NEW `internal/tools/sslyze/sslyze.go` (factory + buildArgs + URL→hostport derivation)
- NEW `internal/tools/sslyze/parse.go` (top-level dispatch; per-server iteration; pluginRules table dispatch)
- NEW `internal/tools/sslyze/rules.go` (per-plugin rule functions; ruleProtocolSupported factory; ruleCertificateInfo multi-finding; helpers)
- NEW `internal/tools/sslyze/severity.go` (per-plugin severity + CWE tables; first multi-rule severity table in M6)
- NEW `internal/tools/sslyze/sslyze_test.go` (11 tests: construction + BuildArgs + ParseOutput integration)
- NEW `internal/tools/sslyze/rules_test.go` (17 tests: per-rule + helpers + table-alignment)
- NEW 6 testdata fixtures + README
- Companion `shieldscan-docs/` commit lands TOOL-ARCH §6.5 invocation literal patch

**28 net-new tests at 6.4 close** (within 22-28 band; high end reflects 13 per-plugin rule cases). Engine total: **222 tests** across 12 packages. Race-clean, vet-clean, golangci-lint v2 reports 0 issues.

**Architecturally significant first-instance patterns (both tracked for promotion):**
1. **"Plugin-rules parser" / "synthetic-finding parser"** — output is structured plugin diagnostics, NOT a finding list. Parser SYNTHESIZES findings via per-plugin domain rules. See entry 4 below.
2. **"Domain-rules severity mapping"** — multi-rule severity + CWE tables driven by exploit-class judgments. See entry 5 below.

**SPEC §7.3 schema-extension trigger fired** — third reductions tool. Path A approved: defer extension proposal to M6 close. See entry 1 below.

**First-time-populated dormant RawFinding fields:** `CipherSuite` (cipher findings via summarizeCiphers metadata) — wait, see entry 2 caveat — and `CertSubject` (cert findings, populated for every issue from the same deployment). Both fields defined since 5.1; M6.4 finally exercises CertSubject. (CipherSuite remains technically dormant: per H.NEW.3 cipher findings emit aggregated per-protocol with cipher names folded into Description; the CipherSuite field is reserved for future single-cipher granularity per H.NEW.3 Option P. Surfaced as nuance in entry 2.)

**Python-side cross-repo verification completed pre-implementation** per workflow step 3: `shieldscan-api/src/app/models/raw_findings.py` lines 122-124 confirm `cipher_suite` (255-char) + `cert_subject` (500-char) columns exist, nullable, generously sized for our values. No blocker.

**4th instance** of `SHIELDSCAN_<TOOL>_BINARY` pattern (DEVELOPMENT-PATTERNS.md Pattern 2 from 6.5) — applies cleanly; no documentation update needed.
**4th instance** of jsonx helpers — reinforces but no expansion.

### 2026-05-02 — Task 6.4: SPEC §7.3 schema-extension trigger FIRED; Path A approved (defer to M6 close)

**Pin (load-bearing).** Reductions counter at 6.4 close:

| Tool | Reductions | Notes |
|---|---|---|
| 6.1 Nuclei | 3 | CVE folded, CVSS-vector dropped, References dropped |
| 6.2 Semgrep | 0 | Every Semgrep datum maps to existing RawFinding fields |
| 6.5 Gitleaks | 5 | Commit-metadata folded, entropy/columns/endline/tags dropped |
| 6.4 SSLyze | 5 | cipher key_size/openssl_name folded, cert chain depth dropped, path_validation/ocsp dropped, plugin metadata dropped, per-plugin aggregation context lost |

**3 of 4 M6 tools have meaningful reductions (75%).** Threshold (3+) met — SPEC §7.3 schema-extension trigger fired.

**Path A approved** (defer extension proposal to M6 close). Reasoning:
1. Biggest "missing fields" (CipherSuite + CertSubject) **already exist** at SPEC §4 line 360-361 — they were dormant. 6.4 finally populates CertSubject. The schema gap is narrower than the raw count suggests.
2. Remaining reductions are diagnostic-fold candidates (cipher key_size, cert chain depth, path_validation, ocsp_response) — stable degradation via Description fold.
3. Cross-repo SPEC §7.3 changes are heavy-coordination (Python `RawFinding` SQLAlchemy model in `shieldscan-api/src/app/models/raw_findings.py` would need migration). Mid-M6 timing fragments milestone focus.
4. Better timing: at M6 close, propose with comprehensive 8-tool data (rather than reactive at 6.4 with 4 datapoints). M9 AI pipeline proposal context will inform what extensions matter.

**Revisit triggers pinned:**
- M6 close milestone-boundary work (primary)
- Mid-M6 customer report of meaningful data loss from a specific reduction (secondary; emergency-extension only if customer-blocking)

### 2026-05-02 — Task 6.4: CertSubject first populated (CipherSuite still dormant — nuance)

**Pin.** `events.RawFinding.CertSubject` (events/events.go:146) — defined at M5.1, **first populated at M6.4** by `ruleCertificateInfo` from leaf cert subject `rfc4514_string`. Cross-repo Python schema accepts (`raw_findings.py:124`, 500-char cap; our values typically <100 chars).

**`CipherSuite` (events/events.go:145) caveat — still dormant.** Per H.NEW.3 Option Q (per-protocol-aggregated), 6.4's protocol findings fold accepted-cipher names into Description as a comma-separated list. The single `CipherSuite` field is reserved for future single-cipher granularity (H.NEW.3 Option P, deferred until customer demand). So **CertSubject is the only formerly-dormant field actually populated at 6.4.**

**Revisit trigger for CipherSuite activation:** customer asks for per-cipher granularity (Option P transition) OR M9 AI pipeline value-add from per-cipher dedup.

### 2026-05-02 — Task 6.4: Plugin-rules parser pattern (1st instance; track for promotion)

**Pin.** SSLyze's `--json_out` payload is structured plugin diagnostics, NOT a finding list. The 6.4 parser dispatches via a per-plugin rules table (`pluginRules` in `rules.go`) where each rule function has signature:

```go
type ruleFunc func(pluginEntry map[string]any, targetHostport string) []events.RawFinding
```

Each rule synthesizes 0..N RawFindings from the plugin's `result` map. Rules return empty slice for "not vulnerable" cases so the dispatcher skips silently. Plugins not in the table are silently ignored (forward-compat with future SSLyze versions).

**Architectural distinction from prior M6 parsers:**
- 6.1 Nuclei: iterate JSONL lines → each line IS a finding
- 6.2 Semgrep: iterate `results[]` → each item IS a finding
- 6.5 Gitleaks: iterate JSON array → each item IS a finding
- 6.4 SSLyze: iterate per-plugin diagnostic results → SYNTHESIZE findings via domain rules

**1st instance of "plugin-rules parser" / "synthetic-finding parser" pattern in M6.** Track for promotion at 3rd instance per project's three-instance threshold.

**Likely future instances:**
- 6.6 Wapiti — per-vuln-class plugins (XSS, SQLi, file-disclosure, etc.) — likely uses similar dispatch
- 6.7 Dep-Check — per-dependency CVE chains may need similar synthesis
- M9 AI pipeline watch: pluginRules table is package-private at 6.4; richer access (per-rule severity overrides driven by org policy) is M9-pipeline-extension concern.

**Future task authors:** grep `"plugin-rules parser"` or `"synthetic-finding parser"` in DRIFT-LOG to find this 1st-instance precedent + dispatch shape. When 3rd instance lands, promote to DEVELOPMENT-PATTERNS.md as Pattern 3.

### 2026-05-02 — Task 6.4: Domain-rules severity mapping (1st instance; track for promotion)

**Pin.** `internal/tools/sslyze/severity.go` exposes two package-private maps:
- `pluginSeverity map[string]string` — FindingType → canonical severity
- `pluginCWE map[string]string` — FindingType → canonical CWE

15 entries each, aligned (TestPluginSeverityCWE_TablesAligned regression-guards).

**Distinct from prior M6 severity tables:**
- 6.1 Nuclei: identity (5 levels, no transformation)
- 6.2 Semgrep: 3-level → 5-level mapping (ERROR→high, WARNING→medium, INFO→info)
- 6.5 Gitleaks: constants-only (no per-finding variation)
- 6.4 SSLyze: **multi-rule domain-knowledge table** with 15 distinct FindingType→severity mappings + 5 distinct CWEs across the table

Domain rationale documented inline in severity.go (critical = confirmed-exploitable + remote; high = active exploitation vectors; medium = deprecated/conditions-required; low = defense-in-depth absences).

**1st instance of "domain-rules severity mapping" pattern.** Track for promotion at 3rd instance. Likely candidates: 6.6 Wapiti (per-vuln-class severity), 6.7 Dep-Check (CVSS-driven). Search `"domain-rules severity mapping"` for trigger.

### 2026-05-02 — Task 6.4: ExitCodeLenient=false naturally-clean (2nd instance)

**Pin.** SSLyze 6.1.0 verified at pre-prep: exits 0 even with weak ciphers / vulnerable findings. Naturally-clean exit-code pattern, **2nd instance after 6.1 Nuclei** in M6's three-pattern exit-code vocabulary (naturally-clean / runner-tolerates / configuration-not-leniency).

**Sub-note: HSTS detection deferred.** TOOL-ARCH §6.5 line 598 mentions "Missing HSTS header" but `--http_headers` plugin is `NOT_SCHEDULED` by default. Per H.6 lean: HSTS detection deferred to DAST layer (Nuclei templates own HTTP-header policy). Trigger to revisit: M9 AI pipeline finds value in cross-tool HSTS deduplication, OR customer ask.

### 2026-05-02 — Task 6.4: PYTHONWARNINGS=ignore defense-in-depth (2nd instance)

**Pin.** `NewSSLyzeRunner` populates `Env = []string{"PYTHONWARNINGS=ignore"}` despite no observed warnings in 6.1.0 pre-prep testing. Defense-in-depth against forward-compat (future SSLyze versions adding opentelemetry-style imports that trip pkg_resources deprecation, à la 6.2 Semgrep).

**2nd instance of Env-warning-suppression pattern after 6.2.** Not yet at promotion threshold (3rd instance — likely 6.6 Wapiti or 6.7 Checkov). Search `"PYTHONWARNINGS"` in DRIFT-LOG for trigger candidates.

### 2026-05-02 — Task 6.4: Per-target invocation strategy (Option X over Y)

**Pin.** SSLyze accepts multiple targets per invocation (`sslyze a.com b.com c.com`), but 6.4 invokes **per-target** (one Run per target — Option X over batch Option Y).

**Rationale:**
- Symmetric with chassis (other M6 tools take one Target per Run)
- Subprocess overhead negligible for SSL scans (~5-10s per target; ~50ms subprocess startup)
- Avoids forcing multi-target abstraction on Target/ScanConfig
- Per-target failures don't pollute other targets' results
- Parser still handles multi-server `server_scan_results` array gracefully (forward-compat if 6.8 wiring decides to batch)

**Revisit trigger:** customer with very-many-target SSL portfolios (50+ targets per scan) where subprocess overhead becomes meaningful (50ms × 50 targets = 2.5s; vs single-batch handshake ~5s reuse).

### 2026-05-02 — Task 6.4: Cipher granularity Option Q (per-protocol-aggregated)

**Pin.** Per H.NEW.3 lean Q approved: weak-cipher findings emitted **per-protocol** (e.g., one finding for "TLS 1.0 supported" with accepted-cipher names folded into Description), NOT per-cipher (Option P which would yield 12 findings for 12 weak ciphers).

**Truncation format:** `"Accepted ciphers (N): A, B, C, D, E, [+M more]"` — first 5 ciphers inline, rest folded into `[+N more]` marker. Description capped at 2 KiB via `jsonx.Truncate` (consistent with 6.2/6.5 conventions).

**Implementation:** `summarizeCiphers` helper in rules.go; regression-guarded by `TestSummarizeCiphers` table-driven test (empty, 3-inline, 12-truncated, 2 KiB-cap-respected).

**Revisit trigger:** customer asks for per-cipher granularity (Option P transition) — would activate the dormant `CipherSuite` RawFinding field per finding.

### 2026-05-02 — Task 6.4: Field-map reductions documented (5; counter 3/4 = 75%)

**Pin.** SSLyze emits 18 plugin shapes with rich diagnostic data. **5 reductions applied:**

| Reduction | Disposition | Why |
|---|---|---|
| `cipher_suite.key_size` + `openssl_name` + `ephemeral_key.*` | Folded into Description (cipher list summary) | No dedicated fields; aggregated per Option Q |
| `received_certificate_chain[1+]` (intermediate + root certs) | Dropped (only leaf → CertSubject) | Single CertSubject field; chain depth lost |
| `path_validation_results` (multi-truststore validation) | Dropped | Aggregate fold deemed too noisy; AI pipeline can re-derive |
| `ocsp_response`, `signed_certificate_timestamps_count` | Dropped | Diagnostic, not directly actionable |
| Plugin metadata (`uuid`, `network_configuration`, `connectivity_status`, plugin-level `error_trace`, per-plugin aggregation counts) | Dropped | Tool internals; aggregation context lost |

**Counter status:** Nuclei=3, Semgrep=0, Gitleaks=5, SSLyze=5. **3 of 4 M6 tools have reductions** — SPEC §7.3 trigger fired (entry 1).

### 2026-05-02 — Task 6.4: Plan §6.4 thinness divergence

**Pin.** Plan §6.4 (`shieldscan-docs/IMPLEMENTATION-PLAN.md` lines 1874-1882): one sentence implementation pointer ("parse SSLyze JSON, detect SSL 2.0/3.0 support, weak ciphers, invalid certificate chain, missing HSTS"). Mentions 4 detection categories.

**Divergence (deepest in M6):** 1 sentence → 28 tests → 13 plugin-interpretation rules → ~750 LoC src + ~600 LoC tests across 4 source files + 2 test files. Plan literal mentions HSTS but `--http_headers` plugin is NOT_SCHEDULED by default; HSTS deferred to DAST layer per H.6.

Plan §6.4 was written before M5 + 6.1/6.2/6.5 chassis; pattern-promotion triggers (jsonx, plugin-rules), the SPEC §7.3 trigger, and the rules-engine architecture didn't exist when plan was authored. Honored in spirit, expanded in scope. Plan §6.4 will benefit from a milestone-boundary refresh at M6 close.

### 2026-05-02 — Task 6.4: TOOL-ARCH §6.5 --regular surgical patch

**Pin.** Companion docs commit (`shieldscan-docs/`) updates TOOL-ARCH §6.5 invocation literal:
- BEFORE: `sslyze --json_out=- --regular target.com`
- AFTER: `sslyze --json_out=- --certinfo --heartbleed --robot --openssl_ccs --reneg --sslv2 --sslv3 --tlsv1 --tlsv1_1 --tlsv1_2 --tlsv1_3 --compression --fallback --ems target.com:443`

**Why.** `--regular` is **invalid in SSLyze 6.1.0** (errors: `unrecognized arguments: --regular`). Verified empirically at pre-prep. The literal was stale from an early SSLyze version; M6.4 implementation enumerates the actual plugin flags used.

**No other prose changes.** Other §6.5 references (binary path, parser-produces example, etc.) remain accurate.

**Regression-guarded by `TestBuildArgs_NoRegularFlag`** (engine-side test asserts `--regular` is NOT in BuildArgs output).

### 2026-05-02 — Task 6.4: Per-target target syntax (hostname:port from URL)

**Pin.** `deriveBuildArgsTarget` in sslyze.go:
- Parses `target.URL` as URL
- Returns `<host>:<port>` where port comes from URL or defaults to 443 for `https`/`wss` schemes
- Falls back to `target.URL` verbatim on parse failure (operator-supplied "host:port" string)

**Examples:**
- `https://app.example.com` → `app.example.com:443`
- `https://app.example.com:8443/path` → `app.example.com:8443`
- `app.example.com:443` (no scheme) → `app.example.com:443` (verbatim fallback)

Regression-guarded by `TestBuildArgs_TargetIsTrailing`.

### 2026-05-02 — Task 6.4: jsonx-extension trigger watch (path-walker; 1st instance need)

**Pin (forward-look).** SSLyze rules walk 2-3 levels deep into nested plugin results (e.g., `result.certificate_deployments[0].verified_chain_has_sha1_signature`). Composing `jsonx.ExtractMap(jsonx.ExtractMap(result, "X"), "Y")` works but is verbose.

A `jsonx.ExtractStringPath("a.b.c", root)` walker would simplify. **NOT extracted at 6.4 (1st-instance need; YAGNI applies).**

**Track for promotion at 3rd instance.** Likely candidates:
- 6.7 Dep-Check (deep CVE chain context likely needs path traversal)
- 6.6 Wapiti (per-plugin-class JSON shapes may nest similarly)

Future task authors: grep `"path-walker"` in DRIFT-LOG for this 1st-instance precedent. When 3rd instance lands, extend jsonx package with the walker (separate file or expanded jsonx.go) and update all 3 callsites atomically (same pattern as 6.5 jsonx extraction).

**Also tracked: `boolFrom` helper.** Used in rules.go for lenient bool extraction. 1st instance; if 4th tool needs the same shape, promote to `jsonx.ExtractBool`.

---

### 2026-05-02 — Task 6.5: Gitleaks native runner + jsonx extraction + env-var-binary pattern promotion

**Files shipped (atomic single commit):**
- NEW `internal/tools/jsonx/jsonx.go` (~80 LoC, 6 helpers)
- NEW `internal/tools/jsonx/jsonx_test.go` (9 tests, table-driven)
- NEW `internal/tools/gitleaks/gitleaks.go` (factory + buildArgs)
- NEW `internal/tools/gitleaks/parse.go` (JSON-array parser + commitFold + recordToFinding)
- NEW `internal/tools/gitleaks/gitleaks_test.go` (16 tests with goleak TestMain)
- NEW 4 testdata fixtures + README
- UPDATE `internal/tools/nuclei/parse.go` (delete 6 helpers; import jsonx)
- UPDATE `internal/tools/semgrep/parse.go` (delete 6 helpers; import jsonx)
- UPDATE `DEVELOPMENT-PATTERNS.md` (add Pattern 2: env-var-binary resolution)

**25 net-new tests at 6.5 close** (16 gitleaks + 9 jsonx; within 23-27 band). Engine total: **194 tests** across 11 packages. Race-clean, vet-clean, golangci-lint v2 reports 0 issues.

**Three first-instance patterns landed at 6.5:**
1. **Constants-only field mapping** (`SeverityCritical = "critical"`, `CWEHardcodedCredentials = "CWE-798"` — no per-finding mapping function). Tracked for promotion at 3rd instance.
2. **Configuration-not-leniency** exit-code handling (`ExitCodeLenient=false` + `--exit-code=0` flag in BuildArgs). Third option in M6's exit-code vocabulary.
3. **JSON-array parse format** (`[]any` with per-item type-assert per H.6). Third format observed in M6.

**Two pattern promotions** (per project's three-instance threshold — both fired atomically at this commit):
1. **Helper extraction** → `internal/tools/jsonx/`. The 6 helpers (`ExtractString`, `ExtractMap`, `ExtractStringSlice`, `ExtractFloat`, `FirstString`, `Truncate`) extracted from `internal/tools/semgrep/parse.go` (most recent canonical instance). Three callsites updated atomically: nuclei, semgrep, gitleaks.
2. **`SHIELDSCAN_<TOOL>_BINARY` env pattern** → `DEVELOPMENT-PATTERNS.md` Pattern 2. Cross-references all three instances explicitly.

**Reductions counter update:** 2 of 3+ tools with field-map reductions (6.1 Nuclei: 3 reductions; 6.2 Semgrep: 0; 6.5 Gitleaks: 5). Threshold for SPEC §7.3 schema-extension trigger not yet hit; track loosely. Likely fires at 6.4 SSLyze or 6.7 Dep-Check.

**Atomic-change reasoning honored.** All 5 file changes + 2 doc updates landed in one engine commit. No interim states where jsonx exists without callers, or where one of nuclei/semgrep imports a not-yet-existent package.

### 2026-05-02 — Task 6.5: SeverityCritical + CWEHardcodedCredentials constants (FIRST constants-only mapping in M6)

**Pin.** `internal/tools/gitleaks/gitleaks.go` exports two package constants:

```go
const (
    SeverityCritical        = "critical"
    CWEHardcodedCredentials = "CWE-798"  // Use of Hard-coded Credentials
)
```

**Why constants, not a function.** Gitleaks emits no per-finding severity or CWE — both are tool-class invariants. Secrets in source are exploit-class by definition (→ critical). CWE-798 covers every Gitleaks rule semantically. A `mapSeverity()` function with no input variation would be misleading scaffolding.

**Exported** so M9 AI pipeline + downstream tooling can reference canonically (e.g., `gitleaks.SeverityCritical` instead of string-literal `"critical"`). Capitalized per Go export convention.

**Trigger to revisit.** Gitleaks 8.x or 9.x ships per-rule severity / CWE fields. At that point, replace constants with a real mapping function driven by the new fields.

**Pattern tracking.** First constants-only mapping in M6. **Track for 3rd-instance promotion** — possible candidates: 6.7 Dep-Check (might constants its category), some 6.6 tool with single-rule output. Search future task DRIFT-LOG entries for "constants-only mapping" to find the trigger.

### 2026-05-02 — Task 6.5: Commit-metadata fold all-or-nothing format

**Pin.** Gitleaks emits per-finding commit metadata in `git` mode (`Author`, `Email`, `Commit`, `Date`, `Message`). RawFinding has no dedicated home for commit context. Decision: **fold into `Description`** when Commit + Author + Date are ALL non-empty. All-or-nothing.

**Format:**
```
"<base description> (commit <SHA8> by <Author> on <YYYY-MM-DD>)"
```

- `Commit` → first 8 chars (short SHA convention from git)
- `Date` → trimmed to `YYYY-MM-DD` (RFC3339 timestamp's time component dropped). Date is what's actionable; the time adds noise without value.
- `Author` → verbatim (already anonymized to `"Anonymous Developer"` etc. in fixtures).

**Email + Message dropped.** Email duplicates Author for attribution; commit Message is too noisy for the Description (single-line append, full commit messages can be paragraphs). Reductions tracked in DRIFT-LOG entry 4 below.

**All-or-nothing rule** (regression-guarded by `TestCommitFold_PartiallyMissing`): if any one of Commit/Author/Date is empty, return base unchanged. Avoids partially-populated suffixes like `"(commit  by  on 2026-01-15)"` that look like a bug. `dir`-mode scans (no git context) and edge cases (commits without authors, repos without dates) all return clean base descriptions.

**Date-trim regression-guarded** by `TestCommitFold_DateTrimsTimestamp`. The time component MUST NOT survive the fold.

### 2026-05-02 — Task 6.5: field-map reductions (5 reductions; counter 2/3+ for SPEC §7.3 trigger)

**Pin.** Gitleaks emits 18 per-finding fields; RawFinding has no exact home for several. **5 reductions applied:**

| Reduction | Disposition | Why |
|---|---|---|
| `Author` + `Email` + `Commit` + `Date` + `Message` | Folded into `Description` (all-or-nothing per entry 3) | No commit-metadata fields on RawFinding; fold preserves attribution without lossy individual drops |
| `Entropy` | Dropped | Diagnostic, not actionable; AI pipeline can re-derive |
| `StartColumn` + `EndColumn` | Dropped | RawFinding has no column field |
| `EndLine` | Dropped | RawFinding has only `CodeLine` (start) |
| `Tags` | Dropped | Tool-specific; OWASP field would be wrong fit |

**Plus three "fully dropped" fields (already-redundant, not counted toward reductions):** `Secret` (duplicates `Match`), `SymlinkFile` (rare + not actionable), `Fingerprint` (Gitleaks's own dedup id; we compute via `tools.ComputeFingerprint`).

**Counter for SPEC §7.3 schema-extension trigger:**
- M6.1 Nuclei: 3 reductions (CVE folded, CVSS-vector dropped, References dropped)
- M6.2 Semgrep: 0 reductions
- M6.5 Gitleaks: 5 reductions

**2 of 3+ tools have reductions.** Threshold for schema-extension proposal is 3+. Track loosely; likely fires at 6.4 SSLyze (CVSS detail fields beyond float64 score) or 6.7 Dep-Check (CVE chain context). Don't preempt.

### 2026-05-02 — Task 6.5: ExitCodeLenient=false + --exit-code=0 (configuration-not-leniency; THIRD M6 exit-code option)

**Pin.** `NewGitleaksRunner` sets `ExitCodeLenient: false` and `BuildArgs` includes `--exit-code=0`. The runner stays strict; the *tool's flag* compensates.

**Third documented pattern** in M6's exit-code vocabulary:

| Pattern | Used at | Tool behavior | Runner config |
|---|---|---|---|
| **Naturally-clean** | 6.1 Nuclei | Tool exits 0 on findings | `ExitCodeLenient=false` (no special handling) |
| **Runner-tolerates** | 6.2 Semgrep | Tool exits non-zero legitimately; no flag to suppress | `ExitCodeLenient=true` |
| **Configuration-not-leniency** | 6.5 Gitleaks | Tool exposes `--exit-code=0`-style flag to force clean exit | `ExitCodeLenient=false` + flag in BuildArgs |

**Decision tree** for future M6/M7 tools (preferred order):

1. Does the tool always exit 0 on success? → naturally-clean (6.1).
2. Does the tool expose a flag to force-clean exit (`--exit-code=0`, `--no-fail-on-finding`, etc.)? → configuration-not-leniency (6.5). Preferred when available — keeps runner config strict, exit semantics owned by tool config (more discoverable from BuildArgs reading).
3. Otherwise → runner-tolerates (6.2).

**Promotion to DEVELOPMENT-PATTERNS.md** when 3+ tools use configuration-not-leniency. Currently 1 instance; track via this DRIFT entry. Search future task entries for "configuration-not-leniency" to find the trigger.

**Regression-guarded by `TestBuildArgs_ExitCodeZeroPresent`.** If a future change removes `--exit-code=0` without updating ExitCodeLenient, Gitleaks would fail every job that finds secrets — the test catches it.

### 2026-05-02 — Task 6.5: helper-extraction promoted to internal/tools/jsonx/

**Pin.** Three-instance threshold met at 6.5 (Nuclei + Semgrep + Gitleaks all need the same lenient `map[string]any` extraction helpers). Helpers extracted to a shared package:

```
internal/tools/jsonx/
├── jsonx.go         (~80 LoC; 6 exported helpers)
└── jsonx_test.go    (9 tests, table-driven)
```

**Exported helpers:**
- `ExtractString(map[string]any, string) string`
- `ExtractMap(map[string]any, string) map[string]any`
- `ExtractStringSlice(map[string]any, string) []string`
- `ExtractFloat(map[string]any, string) float64`
- `FirstString([]string) string`
- `Truncate(string, int) string`

**Verbatim copy** from `internal/tools/semgrep/parse.go` (most recent canonical instance) — no behavioral changes. Pre-extraction nuclei + semgrep test suites passed; post-extraction same suites still pass — verified.

**Atomic commit invariants honored:**
- jsonx exists ⇔ 3 callers exist (nuclei, semgrep, gitleaks)
- All 3 callers updated together
- DEVELOPMENT-PATTERNS.md entry exists ⇔ 3rd instance exists

**Future expansion** (not at 6.5): `ExtractInt`, dotted-path walkers (`ExtractStringPath("a.b.c")`), structured access for known-shape JSON. Driven by genuine 4th-tool need; YAGNI applies.

**Test coverage:** type-assertion boundaries (nil map, missing key, wrong type), array-or-bare-string tolerance, JSON-number-as-float64 contract, regression guard documenting that ExtractString does NOT walk dotted paths (composition via ExtractMap chaining instead).

### 2026-05-02 — Task 6.5: SHIELDSCAN_<TOOL>_BINARY pattern promoted to DEVELOPMENT-PATTERNS.md

**Pin.** Three-instance threshold met at 6.5. The env-var-binary resolution pattern (`SHIELDSCAN_<TOOL_UPPER>_BINARY` env, `exec.LookPath("<tool>")` fallback, fail-fast on neither) lands as `DEVELOPMENT-PATTERNS.md` Pattern 2 (after Pattern 1 trigger-based deferral from 5.5).

**Instances cross-referenced explicitly:**
- M6.1 Nuclei (`internal/tools/nuclei/nuclei.go`)
- M6.2 Semgrep (`internal/tools/semgrep/semgrep.go`)
- M6.5 Gitleaks (`internal/tools/gitleaks/gitleaks.go`)

**Phase 1 startup wiring (fail-fast diagnostic) deferred to 6.8** per M6.5 watch item E. 6.5 ships only the resolution interface (`Config.BinaryPath` field per tool); 6.8 wires `cmd/worker/run.go` to invoke env-var resolution and emit the diagnostic. The pattern entry in DEVELOPMENT-PATTERNS.md documents the Phase 1 message shape so 6.8's author has the canonical text.

**Trigger to revisit pattern.** A native tool with a fundamentally different launch mechanism (Java `java -jar <path>`, Python `python -m <module>`, etc.). Likely extends to a launcher abstraction rather than fragmenting per-tool.

### 2026-05-02 — Task 6.5: Plan §6.5 thinness divergence

**Pin.** Plan §6.5 (`shieldscan-docs/IMPLEMENTATION-PLAN.md` lines 1886-1894): one sentence implementation pointer ("parse JSON output, every finding is critical severity with CWE-798"). No test names. No construction surface. No mention of helper-extraction or pattern-promotion triggers.

**Divergence:** 1 test → 25 tests; ~25 LoC test → ~750 LoC across 5 file changes + 2 doc updates.

Plan was written before M5 + 6.1/6.2 chassis; pattern-promotion triggers (jsonx, env-var-binary) didn't exist when plan was authored. Honored in spirit (Severity + CWE constants assertion ARE present in tests), expanded in scope. Plan §6.5 will benefit from a milestone-boundary refresh at M6 close; no surgical patch at this commit.

### 2026-05-02 — Task 6.5: reductions counter (2/3+; SPEC §7.3 schema-extension trigger pending)

**Pin.** SPEC §7's `RawFinding` schema reductions counter:
- 6.1 Nuclei: 3 reductions
- 6.2 Semgrep: 0 reductions
- 6.5 Gitleaks: 5 reductions

**Threshold:** 3+ tools with field-map reductions for SPEC §7.3 schema-extension proposal. Currently 2 of 3+. Don't preempt; track loosely.

**Likely candidates for 3rd:**
- **6.4 SSLyze** — TLS-detail fields (cipher suite metadata, certificate chain context) likely don't fit existing RawFinding shape.
- **6.7 Dep-Check** — CVE chain context (vulnerability ID + dependency tree path) likely needs accommodation.

**When the 3rd tool with reductions lands**, that task's commit body should call out the threshold-trigger fire, and propose either (a) RawFinding schema extension, or (b) explicit "no extension; reductions are intentional" decision with reasoning. SPEC §7.3 is the natural home for the proposal.

### 2026-05-02 — Task 6.5: JSON-array parse format (THIRD M6 format)

**Pin.** Gitleaks emits a bare JSON array of finding objects:

```json
[
  { /* finding 1 */ },
  { /* finding 2 */ }
]
```

**Third format observed in M6:**
- **6.1 Nuclei:** JSONL — newline-separated single-line objects, parsed via `bufio.Scanner` line loop.
- **6.2 Semgrep:** Single-doc JSON `{"results": [...], "errors": [...]}`, parsed via single `json.Unmarshal`.
- **6.5 Gitleaks:** Bare JSON array `[...]`, parsed via single `json.Unmarshal` into `[]any`.

**Decode shape: `[]any` with per-item type-assert** (per H.6 lean). More tolerant than `[]map[string]any`, which would fail-fast on any non-object array element. A malformed record (e.g., a stray string in the array) gets skipped with WARN rather than failing the whole `Unmarshal`.

**Regression-guarded by `TestParseOutput_MalformedJSONFatal`** (top-level malformed JSON IS fatal — distinct from 6.1's per-line drop-and-continue) and `TestParseOutput_MissingRequiredFieldsSkipped` (per-record missing fields skip with WARN, batch survives).

### 2026-05-02 — Task 6.5: constants-only mapping pattern (1st instance; track for promotion at 3rd instance)

**Pin (forward-look).** Gitleaks's constants-only mapping (no `mapSeverity()` function; severity + CWE are package constants) is the **first instance** in M6 of a tool whose finding shape doesn't vary along severity/CWE axes.

**Pattern shape:** when a tool emits no per-finding severity field AND no per-finding CWE field, the runner package exports constants for both (capitalized for export) and applies them universally in `recordToFinding`. No mapping function; no severity.go file; constants-only.

**Track for 3rd-instance promotion.** Possible candidates:
- **6.7 Dep-Check** — every dep-check finding is essentially "outdated dep with known CVE"; severity might be CVSS-driven (not constant) — likely NOT this pattern.
- **6.6 Wapiti / Nikto** — DAST tools that may have per-finding severity. Likely NOT this pattern either.
- **Less obvious:** any future tool whose category is intrinsically uniform-severity (e.g., a license-compliance scanner where every finding is "license-policy-violation" → fixed severity).

**Future task authors:** grep for "constants-only mapping" in DRIFT-LOG to find this trigger and the 1st-instance precedent. When the 3rd instance lands, promote to DEVELOPMENT-PATTERNS.md as Pattern 3.

---

### 2026-05-01 — Task 6.2: Semgrep native runner

**Files shipped:** `internal/tools/semgrep/semgrep.go` (factory + buildArgs closure) · `internal/tools/semgrep/parse.go` (single-doc JSON parser + extraction helpers — second instance) · `internal/tools/semgrep/severity.go` (first non-identity M6 severity table) · `internal/tools/semgrep/semgrep_test.go` (17 tests with goleak TestMain) · 6 testdata fixtures (4 from real-anonymized + synthetic runs: basic, multi, empty, error; 2 hand-crafted: unknown_fields, missing_fields) + testdata README.

**17 tests at 6.2 close.** Engine total: **169 tests** across 10 packages. Race-clean, vet-clean, golangci-lint v2 reports 0 issues.

**Three "first non-trivial" patterns landed at 6.2** (see entries 1, 3, 5 below): first non-identity severity mapping, first ExitCodeLenient=true real use, first populated NativeRunner.Env. These establish patterns governing 6.4–6.7 inheritance.

**Field-map success: NO reductions needed.** Every meaningful Semgrep datum maps to an existing `events.RawFinding` field — contrast with 6.1's three reductions (CVE folded into Description, CVSS-vector dropped, References dropped). Positive signal. See entry 8 below.

### 2026-05-01 — Task 6.2: severity mapping table (FIRST non-identity in M6)

**Pin.** `mapSeverity()` in `internal/tools/semgrep/severity.go` is the first non-identity severity table in M6. Semgrep emits a 3-level scheme; canonical RawFinding.Severity is 5-level. Mapping:

| Semgrep | Canonical | Why |
|---|---|---|
| `ERROR` | `high` | Exploit-class (RCE, SQLi, secrets). NOT `critical` — critical reserves for confirmed-exploitable + remote (CVSS≥9). ERROR-but-not-critical leaves room for AI pipeline to upgrade-to-critical via context. |
| `WARNING` | `medium` | Best-practice violation (missing CSRF middleware, weak crypto). |
| `INFO` | `info` | Style/maintainability (dead code, naming). |
| empty / unknown | `info` | Defensive default (mirrors 6.1 posture). |

**Load-bearing decision: ERROR → high (NOT critical).** Regression-guarded by `TestMapSeverity_ErrorMapsToHighNotCritical`. Future "simplification" attempts must fail this test rather than silently re-map.

**Case-insensitive.** Folded into `TestMapSeverity_AllLevels` table (per H.10 trim — single test covers both axes).

### 2026-05-01 — Task 6.2: CWE prefix-extraction (load-bearing format note)

**Pin.** Semgrep emits `extra.metadata.cwe` as an array of strings of the form `"CWE-78: Improper Neutralization of Special Elements..."` — CWE id embedded in human-readable description. Contrast with Nuclei (6.1) which emits bare `"CWE-78"` strings.

`cweFromMetadata()` extracts only the `CWE-N` prefix via anchored regex `^(CWE-\d+)`. Empty input or no match → `""`. Anchored at start (^) — won't accept "WCWE-78" or other malformed prefixes.

**Why prefix-only.** Consistency with Nuclei's bare format keeps the `RawFinding.CWEID` field stable across tools; the AI pipeline can lookup the human-readable description from a CWE catalog if needed. Embedded description duplicates the CWE name lookup; storing both in CWEID would create dedup ambiguity.

### 2026-05-01 — Task 6.2: ExitCodeLenient=true (FIRST non-trivial M6 real use)

**Pin.** Semgrep is the first M6 tool with `ExitCodeLenient=true`. Three exit-code regimes the runner must handle:

| Exit | Cause | ParseOutput sees | Behavior |
|---|---|---|---|
| 0 | Clean run with `--config=p/default` (with or without findings) | Full JSON document | Normal parse |
| 1 | Findings with `--error` (we omit), or network/permission edge | Full JSON document | Normal parse (NativeRunner swallows non-zero) |
| 2 | Genuine tool error (parse failure on input file, bad config) | JSON with `errors[]` populated | Log errors at WARN, return parsed results (often empty) — **not** a Go error per H.1 |

**`errors[]` non-empty + `results[]` empty is log-and-continue, NOT fatal.** Symmetric with 6.1's malformed-line tolerance. Trigger to revisit (escalate to partial-fatal): customer report of "Semgrep silently scanned nothing." At that point, gate Option B on `len(results)==0 && len(errors)>0`.

**Mock-binary test** (`TestExitCodeLenient_Exit2WithErrorsArray`) exercises the full NativeRunner.Run pipeline through a Semgrep-configured runner with a shell-script mock that emits the error fixture and exits 2. Distinct from 5.2's framework-level lenient tests by going through the Semgrep factory.

**`--error` flag deliberately omitted.** Keeps exit-code semantics simple (0 on clean run, 2 on tool error). Including would force lenient-mode exercise on every clean run with no operational benefit.

### 2026-05-01 — Task 6.2: --config=p/default privacy decision (telemetry conflict resolved)

**Pin.** Semgrep's `--config=auto` requires telemetry ON. Verified empirically during pre-prep:

```
$ semgrep scan --config=auto --metrics=off vuln-target/
[ERROR]: Cannot create auto config when metrics are off.
         Please allow metrics or run with a specific config.
```

**Decision: `--config=p/default --metrics=off`** — privacy-preserving fixed ruleset. Less adaptive than auto (which tunes the ruleset to detected languages / frameworks), but:

1. **No telemetry to third-party servers.** Operationally aligns with self-host ethos; customers running in air-gapped environments cannot use `auto` regardless.
2. **Predictable.** Rule set is fixed; scan results are reproducible across runs.
3. **`--metrics=off` defense-in-depth.** `p/default` doesn't need metrics, but explicit `--metrics=off` documents intent and survives Semgrep config-default changes.

**Customer-language-specific rulesets deferred** until customer demand. `--config=auto` is also `--config=p/python p/javascript ...` composable; trigger to revisit: customer ask for tiered SAST or language-specific tuning.

**Per-file `--timeout=120`** (folded here): Semgrep's per-file regex timeout, distinct from the outer NativeRunner 5-minute timeout. Protects against pathological regex backtracking on a single file (catastrophic backtracking on minified JS / generated Python). Hardcoded at 120s; configurable promotion deferred until customer demand.

**Companion docs commit lands TOOL-ARCH §6.2 invocation literal patch** to match: `--config=auto` → `--config=p/default --metrics=off --quiet --timeout=120`.

### 2026-05-01 — Task 6.2: PYTHONWARNINGS=ignore Env pattern (forward-pin for pipx tools)

**Pin.** `NewSemgrepRunner` populates `NativeRunner.Env = []string{"PYTHONWARNINGS=ignore"}`. FIRST populated Env in M6.

**Why.** Semgrep 1.95.0 on Python 3.12 emits a `UserWarning: pkg_resources is deprecated` line on stderr at every invocation (from `opentelemetry.instrumentation.dependencies` import). NativeRunner captures stderr only on subprocess error — on success, stderr is discarded — but the warning still mixes into error-context truncation when exit codes ARE non-zero. `PYTHONWARNINGS=ignore` suppresses cleanly.

**NativeRunner appends to inherited env** (per `cmd.Environ()` in 5.2's native.go:148), so PATH/HOME/etc. survive. Test asserts presence in slice (not absolute env equality).

**Forward-pin for other pipx-installed tools.** SECOND instance candidates: M6.4 SSLyze, M6.6 Nikto/Wapiti, M6.7 Checkov — all pipx-installed Python CLI tools likely to emit similar deprecation noise. Pattern: `Env: []string{"PYTHONWARNINGS=ignore"}` per runner. Promotion to DEVELOPMENT-PATTERNS.md at THIRD instance per project convention.

### 2026-05-01 — Task 6.2: setuptools<81 operational note (OPS milestone follow-up)

**Pin (operational).** Semgrep 1.95.0 fails to start on Python 3.12 with setuptools v82 (default in fresh pipx installs as of 2026-04+) due to dropped `pkg_resources` module. Symptom: `ModuleNotFoundError: No module named 'pkg_resources'` from the `opentelemetry-instrumentation-requests` import chain.

**Workaround applied to dev environment:**

```bash
pipx install semgrep==1.95.0
/home/.../share/pipx/venvs/semgrep/bin/python -m pip install 'setuptools<81'
```

**OPS milestone (M11) provision-worker.sh must apply this fix** for every pipx-installed Semgrep target. Likely shape:

```bash
pipx install semgrep==1.95.0
"$(pipx environment --value PIPX_LOCAL_VENVS)/semgrep/bin/python" \
    -m pip install --quiet 'setuptools<81'
```

**Trigger to revisit:** Semgrep 1.96+ (or whichever upstream version drops `pkg_resources` import via opentelemetry upgrade) lands. At that point, the workaround is no longer necessary; remove from provision-worker.sh.

### 2026-05-01 — Task 6.2: Plan §6.2 thinness divergence (1 sentence → 17 tests)

**Pin.** Plan §6.2 (`shieldscan-docs/IMPLEMENTATION-PLAN.md` lines 1805-1814) is even thinner than §6.1: implementation reduced to a single sentence ("parse JSON output, map check_id → finding_type, extract path, start.line, extra.metadata.cwe"). No test names. No construction surface.

**Divergence:** 1 sentence → 17 tests; ~25 LoC test → ~430 LoC test + ~340 LoC src across 3 source files.

Same pattern as 6.1 — plan was written before M5 + 6.1 established the chassis. Honored in spirit, expanded in scope. Plan-staleness reference (no surgical patch to plan literal at this commit; the entire M6 plan section will benefit from a milestone-boundary refresh at M6 close).

### 2026-05-01 — Task 6.2: field-map success (no reductions; positive signal)

**Pin.** Every meaningful Semgrep datum maps to an existing `events.RawFinding` field at SPEC §7's schema. Contrast with 6.1's three reductions (CVE folded into Description, CVSS-vector dropped, References dropped).

| Semgrep field | RawFinding field |
|---|---|
| `check_id` | `FindingType` (and Title — Semgrep has no separate title) |
| `path` | `CodeFile` (FIRST populated) |
| `start.line` | `CodeLine` (FIRST populated) |
| `extra.message` | `Description` |
| `extra.severity` (mapped) | `Severity` |
| `extra.metadata.cwe[0]` (prefix-extracted) | `CWEID` |
| `extra.metadata.owasp[0]` (verbatim) | `OWASP` (FIRST populated) |
| `extra.lines` (truncated 2 KiB) | `CodeSnippet` (FIRST populated) |

**Implication for SPEC §7.3 schema-extension trigger.** Per user guidance: track loosely; if 3+ M6/M7 tools have RawFinding-field reductions (CVE folded, Evidence split, etc.), THAT is the schema-extension trigger. So far: 6.1 had 3 reductions, 6.2 had 0. Counter at 1 tool with reductions; threshold not yet hit.

### 2026-05-01 — Task 6.2: helper-extraction trigger reminder (SECOND instance)

**Pin (forward-look).** `internal/tools/semgrep/parse.go` contains a verbatim copy of the lenient-decode helpers from `internal/tools/nuclei/parse.go`:

- `extractString(map[string]any, string) string`
- `extractMap(map[string]any, string) map[string]any`
- `extractStringSlice(map[string]any, string) []string`
- `extractFloat(map[string]any, string) float64`
- `firstString([]string) string`
- `truncate(string, int) string`

**SECOND instance** of this shape across M6 tools. Per project's three-instance threshold, extraction to a shared package (proposed: `internal/tools/jsonx/`) is triggered at the **THIRD instance**.

**Likely third instance: M6.4 SSLyze** — pipx-installed, JSON output, same lenient-decode shape. **6.4's task author should:**

1. Notice the third instance.
2. Extract helpers to `internal/tools/jsonx/` (new package).
3. Update `internal/tools/nuclei/parse.go` and `internal/tools/semgrep/parse.go` to import from the new package.
4. Land all three changes together (extraction + two callsite updates) so neither tool grows stale.
5. Document the extraction in 6.4's DRIFT-LOG (third-instance threshold met).

**If 6.4 doesn't fit the shape** (different JSON parsing model), the trigger moves to 6.6 / 6.7 — first that fits.

---

### 2026-05-01 — Task 6.1: Nuclei native runner

**Files shipped:** `internal/tools/nuclei/nuclei.go` (factory + BuildArgs closure) · `internal/tools/nuclei/parse.go` (lenient JSONL parser + extraction helpers) · `internal/tools/nuclei/severity.go` (severity map) · `internal/tools/nuclei/nuclei_test.go` (17 tests with goleak TestMain) · 4 testdata fixtures (`nuclei_ssl_multi.jsonl` real-anonymized, `nuclei_xss_basic.jsonl` synthesized, `nuclei_empty.jsonl` empty, `nuclei_malformed_line.jsonl`) + testdata README.

**17 tests at 6.1 close** (vs 16 estimate; +1 from H.3 tool-failure test). Engine total: **152 tests** across 9 packages. Race-clean, vet-clean, golangci-lint v2 reports 0 issues.

**Plan §6.1 thinness divergence.** Plan literal §6.1 (lines 1776-1801) is 1 test, parser-only — it predates M5 and assumes a flat `parseNucleiOutput([]byte)` signature with no construction surface. M5's `NativeRunner` inverts the contract (closure-injected behavior into a generic runner). 6.1 honors the spirit (parse Nuclei output → []RawFinding) but expands scope to match canonical-first-tool weight: 1 test → 17 tests, ~25 LoC test → ~280 LoC test + ~340 LoC src across 3 source files.

**6.1 does NOT register the runner.** `cmd/worker/run.go` registry population is deferred to 6.8 wiring task per landscape Finding 1. The empty-registry WARN at startup (5.6) continues to fire after 6.1 lands; this is acceptable and clears at 6.8. Brief reference here; full plan-staleness DRIFT entry at 6.8.

**ADR-022 candidacy: recon-as-pre-scan-helpers.** Per landscape Finding 2, recon tools (Subfinder, httpx) don't fit ToolRunner because they produce subdomain strings / LiveHosts not RawFindings. Resolution lean: ship parsers + RunRecon helper at 6.3, but don't register with worker.Registry; M8 invokes recon as pre-scan phase. Brief reference here; full DRIFT entry + ADR-022 draft at 6.3 commit time.

### 2026-05-01 — Task 6.1: tool-output lenient decode pattern (load-bearing asymmetry)

**Pin.** Tool-output parsing (`internal/tools/<tool>/parse.go`) decodes lenient `map[string]any` and extracts via type-asserted helpers (`extractString`, `extractStringSlice`, `extractFloat`, `extractMap`). This is **asymmetric** with wire-format strictness in `internal/events/`, which uses `DisallowUnknownFields` and rejects malformed payloads.

**Why the asymmetry.** Tools evolve their JSON shapes between minor releases (Nuclei v3.6 → v3.7 added fields; v3.8 will likely add more). Strict decode would break parsing on every Nuclei update. Wire format is a cross-repo contract — strictness there forces version-pin discipline. Tool output is an upstream artifact — leniency there keeps parsers stable across upstream churn.

**Per-line resilience.** Malformed JSONL lines are dropped with WARN (not fatal). A subprocess killed mid-write or a stray banner leaking into stdout shouldn't poison the whole batch. Fixture `nuclei_malformed_line.jsonl` exercises this (4 valid + 1 garbage line → 4 findings + 1 logged warning).

**Trigger to revisit (promote helpers to shared package).** Three-instance threshold: 6.1 inlines helpers in `internal/tools/nuclei/parse.go`. 6.2 (Semgrep) and 6.4 (SSLyze) likely need same shape; promote to `internal/tools/jsonx/` at the third instance. Don't pre-extract.

### 2026-05-01 — Task 6.1: bufio.Scanner MaxScanTokenSize set to 1 MiB

**Pin.** `parseOutput` allocates `bufio.Scanner` with explicit 1 MiB buffer cap (`maxScanLineBytes = 1 * 1024 * 1024`).

**Why not the default 64 KiB.** Nuclei JSONL records embed full HTTP request + response when a finding matches. Request payloads can be a few KiB; response payloads (full HTML body) can be tens of KiB. Default 64 KiB is regularly insufficient — observed on the SSL fixture's larger records (~3-4 KiB) and easily exceeded on real DAST findings.

**Lines exceeding 1 MiB are dropped with WARN** (`bufio.ErrTooLong` path). Same fail-soft posture as malformed-line handling — the runner returns successfully-parsed findings, doesn't poison the batch.

**Trigger to revisit.** Customer report of "finding visible in `nuclei` stdout but not in our DB" → check warning logs for too-long drops; if present, switch from `bufio.Scanner` to streaming `json.Decoder` over `io.Reader` (no per-line buffer cap, but more code to manage).

### 2026-05-01 — Task 6.1: severity mapping table (Nuclei → canonical)

**Pin.** `mapSeverity()` is identity for all five Nuclei-emitted levels (info, low, medium, high, critical). Empty / unknown / unrecognized inputs default to `"info"` (defensive minimum) rather than dropping the finding.

| Nuclei `info.severity` | RawFinding `Severity` |
|---|---|
| `info` | `info` |
| `low` | `low` |
| `medium` | `medium` |
| `high` | `high` |
| `critical` | `critical` |
| (empty / unknown) | `info` |

**Why pin an identity table.** Code review without it leaves "is severity validated?" ambiguous. The table-as-DRIFT-entry creates the audit trail. Other M6 tools (Semgrep at 6.2 emits `ERROR/WARNING/INFO`; SSLyze at 6.4 has its own scheme) will need genuine non-identity tables and document them in their per-task DRIFT entries.

**Case-insensitive.** `mapSeverity("HIGH")` == `"high"`. Defense in depth; Nuclei is consistent about lowercase, but case-folding costs nothing.

### 2026-05-01 — Task 6.1: CWE extraction path (first-only convention)

**Pin.** CWE extracted from `info.classification.cwe-id[0]` — first element only. If the array is absent or empty, `RawFinding.CWEID = ""`.

**Why first-only.** Nuclei's classification.cwe-id is conventionally a single-element array. Multi-CWE templates exist but are rare; selecting [0] handles the majority case without forcing a "primary CWE" decision into the parser. If a finding genuinely needs multiple CWEs surfaced, it's a SPEC schema extension (CWEs as `[]string`) — not a parser concern.

**SSL templates ship without classification.** `nuclei_ssl_multi.jsonl` fixture has 11 findings, zero have `info.classification`. CWEID is empty for all of them; pinned by `TestParseOutput_NoClassification`.

**CVE id has no dedicated RawFinding field.** SPEC §7's RawFinding schema (events.go:111+) defines CWEID, OWASP, CVSSScore but not CVEID. M6.1 folds the CVE id into Description (`"original description (CVE-2024-1234)"`) so the semantic is preserved without losing data. **Reversible:** if SPEC schema gains a CVEID field, the fold is a one-line removal.

### 2026-05-01 — Task 6.1: Plan §6.1 + SPEC §3.3 surgical patches ("Nuclei SDK" → "Nuclei CLI")

**Pin.** Two one-word doc patches landed at 6.1 docs commit:
- `shieldscan-docs/SPECIFICATION.md:45` — "Nuclei SDK" → "Nuclei CLI"
- `shieldscan-docs/IMPLEMENTATION-PLAN.md:9` — "Nuclei SDK" → "Nuclei CLI"

**Why.** Engine never integrated a Nuclei Go SDK. From M5 design through M6.1 implementation, Nuclei is invoked as a subprocess via `tools.NativeRunner` (5.2 chassis). The doc references to "Nuclei SDK" were stale from an early architecture sketch. M6.1 is the canonical-first-tool task; correcting the references at this point keeps future readers from chasing a non-existent integration.

**No other prose changes.** Surgical: just "SDK" → "CLI" in the two locations. Other Nuclei references in SPEC (e.g., line 230 tree diagram showing `nuclei.go`, line 731 example payload `"engine": "nuclei"`) are correct as-is.

### 2026-05-01 — Task 6.1: Registry redefinition reference (full entry at 6.8)

**Pin (brief).** Plan §6.8 currently says "Create `internal/tools/registry.go`" — but `internal/worker/registry.go` already exists at 5.5 (frozen-at-construction Registry shipped as part of the worker chassis). Per landscape Finding 1, plan §6.8 becomes the *wiring* task: invoking each M6 task's `NewXRunner` factory in `cmd/worker/run.go` and constructing `worker.NewRegistry(map[string]tools.ToolRunner{...})` from the results.

**Full plan-staleness DRIFT entry lands at 6.8** when the wiring is implemented and the redefinition is fully resolved. This entry is the brief reference for searchability.

---

### 2026-05-01 — Task 5.6: worker startup + heartbeat + main.go integration

**Files shipped:** `internal/worker/heartbeat.go` + test (5 tests) · `internal/worker/startup.go` + test (6 tests) · `cmd/worker/main.go` (refactored — Phase 0 ping + signal handling) · `cmd/worker/run.go` (NEW — `runMain(ctx, deps)` extraction per H.12) + test (6 tests) · `deploy/docker-compose.services.yml` + `deploy/docker_compose_test.go` (5 tests) · `internal/worker/processor.go` extension (`NewProcessorFromRedis` convenience constructor) · `internal/config/config.go` extension (`DrainGraceSeconds` field) + test.

**25 net-new tests at 5.6 close** (vs planned 17 — extras: NonExecutableBinaryWarns, NativeBinaryFoundLogsSuccess, RawDoesNotContainSecrets, ShortUUID_Distinct, GenerateWorkerID_Format, DrainGraceDefault). Engine total: **135 tests** across 8 packages. Race-clean, vet-clean, golangci-lint v2 reports 0 issues. Worker binary builds cleanly.

**Worker-lifetime services pattern: 2 instances now (Worker, Heartbeat)**, not yet promoted to DEVELOPMENT-PATTERNS.md per user's H.4 nuance. ADR-021 Rule 3 carve-out covers the pattern; explicit DEVELOPMENT-PATTERNS.md entry awaits a third instance (potential candidates: M6+ metrics emitter, M7.5 warm pool manager, idempotency-cleanup service).

**Force-cancel grace period via select on runDone vs time.After.** Default 60s via `SHIELDSCAN_DRAIN_GRACE_SECONDS` env var (per H.9). Pattern: SIGTERM → workerCtx cancels → main observes → race Worker.Run completion vs grace timer; `os.Exit(2)` if timer wins.

**No forcing-function self-catch on this task specifically.** The 5.5 discrimination semantics retrospective was the M5 highlight; 5.6 is integration-heavy and the patterns are established.

### 2026-05-01 — Task 5.6: Heartbeat as worker-lifetime service

**Pin.** `internal/worker.Heartbeat` is a standalone type implementing the ADR-021 Rule 3 worker-lifetime services carve-out. Receives `workerRootCtx` from `main()` (via `runMain(ctx, deps)`); never constructs `context.Background()` itself.

**Two ctx-aware exit paths** in `Run` loop: `<-ctx.Done()` returns `ctx.Err()`; `<-ticker.C` with write-failure logs at WARN and continues. goleak in `cmd/worker/run_test.go` TestMain verifies leak-clean across tests.

**Currently the second worker-lifetime service after Worker itself.** Pattern not yet promoted to DEVELOPMENT-PATTERNS.md pending third instance. Documented in Heartbeat godoc + this entry. ADR-021 Rule 3 already covers the pattern; explicit DEVELOPMENT-PATTERNS.md entry can wait.

### 2026-05-01 — Task 5.6: TTL-only worker expiry (no Del on shutdown)

**Decision.** `Heartbeat.Run` does NOT `DEL` the worker key on shutdown. Symmetric handling: clean shutdown and crash both rely on TTL expiry (60s default).

**Trade-off acknowledged.** 60s "ghost worker" entries appear in ops dashboards after restart. Operationally low-noise — orchestrator logic should already tolerate the case where a worker key exists but no jobs are being claimed (the orchestrator's worker-routing layer reads the key to decide where to dispatch; a ghost worker briefly looks "available" but jobs queued to it stall and re-dispatch via the ghost-queued janitor).

**Trigger to revisit:** ops dashboards genuinely confused by ghost entries causing incorrect operational decisions (not just the entries' existence). At MVP scale with single-digit workers, the trigger almost certainly never fires. Acceptable.

### 2026-05-01 — Task 5.6: Phase 2 fail-soft at 5.6 (forward-pin to M7)

**Pin.** Startup Phase 2 (Docker services healthcheck) is fail-soft at 5.6 because empty registry means no services to check. Pattern documented in `Startup.checkDockerServices` godoc.

**Trigger to switch from fail-soft to fail-fast:** M7 task constructors register `*DockerServiceRunner` instances with `HealthPath` set, AND the corresponding tool is operationally required (not optional). Each M7 task scope-proposal decides per-tool whether the service warrants fail-fast on health check.

**Same pattern applies to Phase 1** (native binaries). Fail-soft until M6 task constructors register tools that are required vs optional.

**5.6 ships the 4-phase scaffolding;** M6/M7 task scope proposals decide phase semantics per their tool's operational requirements.

### 2026-05-01 — Task 5.6: /health HTTP endpoint deferred to OPS milestone

**Pin.** Worker `/health` HTTP endpoint deferred to OPS milestone. Plan literal §5.6 mentioned `health.go` as a separate file; 5.6 implementation does NOT include it.

**Trigger to revisit:** ops needs runtime worker health observable from outside the worker process. Concrete signals:
- Kubernetes liveness/readiness probes need an HTTP endpoint (when M5+ deploys to K8s).
- Pull-based monitoring infrastructure (Prometheus scraping) needs an exposition endpoint.
- Orchestrator-side worker-routing logic needs a runtime health signal beyond TTL expiry.

**Current 5.6 health surface:**
- Phase 0 Redis ping at startup (fail-fast if Redis unreachable).
- Heartbeat key TTL (orchestrator infers worker liveness from TTL refresh).

These cover MVP without an HTTP `/health` endpoint.

### 2026-05-01 — Task 5.6: empty-registry startup behavior

**Pin.** 5.6 ships with empty `Registry`; M6+ task constructors populate engines via the `worker.NewRegistry(map[string]tools.ToolRunner{...})` call site in `cmd/worker/run.go`.

**Startup logs an explicit WARN** when `Registry.Engines()` returns empty so operators don't silently run a no-op worker. The warning message:

> "worker started with empty registry; no jobs will be processed until tool runners are registered. Tool runners are registered by M6+ task constructors (e.g., NativeRunner for Nuclei in M6.1). If this is unexpected, check that your worker binary was built with the desired M6+ task code."

**Without this warning,** an operator running the 5.6 binary in production would see jobs queue up and never process, with no clear diagnostic. The warning makes the no-tools state actionable.

### 2026-05-01 — Task 5.6: runMain extraction for testability

**Pattern.** `cmd/worker/main.go` delegates the bulk of its assembly + lifecycle to `cmd/worker/run.go`'s `runMain(ctx, deps) int`. main() loads config + builds Redis client + sets up signal-derived ctx; runMain handles dependency wiring, startup phases, Worker spawning, and shutdown drain.

**Why.** Integration tests (`cmd/worker/run_test.go`) exercise the full assembly without invoking signal handling. Test fixtures construct `runMainDeps` directly; tests call `runMain(ctx, deps)` and verify exit codes + Redis-side state.

**main() is small** (under 60 lines after refactor). Responsibilities: config load, log setup, signal context, Redis client + Phase 0 ping, call runMain, exit with returned code. All assembly lives in runMain.

**Side benefit.** runMain serves as documentation of the worker's full dependency graph; reading it shows the entire engine integration in one function.

### 2026-05-01 — Task 5.6: NewProcessorFromRedis convenience constructor

**Pin.** `internal/worker.NewProcessorFromRedis(registry, *redis.Client, log)` added at 5.6 to avoid main package needing to construct values of `worker`'s unexported interface types (`progressPublisher`, `cancelSubscriber`).

**Why this exists.** `ProcessorDeps`'s factory fields take unexported interface types so tests in the worker package can inject mocks. main.go can't construct values of those unexported types from outside the package, so this convenience constructor handles the wiring inside the package.

**Trade-off.** Two constructors (`NewProcessor` for tests, `NewProcessorFromRedis` for production) is mild duplication. Considered alternatives: (a) export the interfaces (renaming would conflict with `redis` package's concrete types of the same names), (b) provide a public DepsBuilder type (over-engineered). Two-constructor approach has the smallest API surface.

### 2026-05-01 — Task 5.6: miniredis BRPOP-ctx-cancel limitation re-encountered in cmd/worker tests

**Repeat occurrence of 5.4's documented limitation.** miniredis's BRPOP runs synchronously and does NOT honor ctx-cancel mid-flight (5.4 DRIFT-LOG entry). cmd/worker integration tests that cancel ctx wait up to `Worker.brpopTimeout = 5s` for the BRPOP to time out naturally before runMain's drain logic activates.

**Effect on test runtime.** Three of six cmd/worker tests run in ~5s each; total cmd/worker test package runtime ~16s. Acceptable for CI; documented here so future eyes don't optimize away the test latency without understanding why it exists.

**Real Redis behavior unchanged.** Worker.Run's ctx-cancel path is correct — go-redis aborts in-flight BRPOP via connection close on real Redis. The test slowness is purely a miniredis artifact.

### 2026-05-01 — M5 milestone-boundary close

**M5 — Go Worker Foundation — closes after Task 5.6.**

| Item | Detail |
|---|---|
| Tasks shipped | 5.1 scaffold + ADRs · 5.2 ToolRunner + NativeRunner · 5.3 DockerServiceRunner · 5.4 Redis primitives · 5.5 worker processor · 5.6 startup + heartbeat + main.go integration |
| Task ordering followed | 5.1 → 5.2 → 5.3 → 5.4 → 5.5 → 5.6 (linear; no reordering) |
| Engine commits | 6 (one per task) |
| Docs commits (shieldscan-docs) | 4 (Checkpoint 2 §6.2 recount · Checkpoint 4 VERSIONS sync · Task 5.1 docs sweep + ADRs · post-5.1 VERSIONS adjustments) |
| Test count | 0 (M5 open) → 16 (5.1) → 35 (5.2) → 59 (5.3) → 88 (5.4) → 110 (5.5) → **135 (5.6 / M5 close)** |
| Engine packages | 8: cmd/worker · deploy · internal/{buildguard, config, events, redis, tools, worker} |
| ADRs added | ADR-016 (raw Redis, not Asynq) · ADR-017 (findings inline + sequencing) · ADR-018 (Streams correction in plan §5.4) · ADR-021 (ctx discipline) |
| ADRs reserved | 019 (cancel Pub/Sub confirmation) · 020 (worker concurrency model) — both promotable from DRIFT-LOG on trigger |
| DEVELOPMENT-PATTERNS.md (engine-side) | 1 pattern: trigger-based deferral (8+ cited instances at promotion time) |
| Cross-repo wire-format fixtures | 2: `internal/events/testdata/job_dispatch_python_v1.json` + `job_completed_python_v1.json` (with .md provenance) |

**Self-catches across M5** (validating forcing-function discipline):

| Task | Catch | Mechanism |
|---|---|---|
| 5.1 | `exec.Command` in own buildguard test | `noctx` linter |
| 5.2 | `ExitCodeIsError` zero-value semantic inverted | TDD writing surfaced design bug |
| 5.4 | ctx-cancel-vs-BRPOP-redis.Nil race losing cancel signal | Debugging miniredis ctx-cancel test |
| 5.5 | discrimination semantics conflation (worker-shutdown vs user-cancel) | Articulating the decision table BEFORE writing conditionals |

The 5.5 retrospective: when conditional logic has 4+ outcomes with different semantic meanings, force-articulate the decision table BEFORE writing the conditionals. The table catches conflations that conditionals silently allow.

**Carry-forwards to M6** (Native Tool Runners):
- Each M6.1-6.7 task constructs a `NativeRunner` instance + registers it via the `worker.NewRegistry(map[string]tools.ToolRunner{...})` map literal in `cmd/worker/run.go`.
- testdata conventions established in 5.1 (`testdata/README.md`); M6.1 Nuclei is the first real consumer with synthetic JSONL fixtures.
- Phase 1 fail-soft → fail-fast trigger lands per-tool at M6 task scope-proposal time.
- ProgressEmitter interface extension trigger fires at M6.3 Recon (per 5.2 H.4 deferral).

**Carry-forwards to M7** (Persistent Docker Service Runners):
- Each M7.1-7.6 task constructs a `*DockerServiceRunner` + populates Registry + adds entry to Startup.DockerSvcs.
- Phase 2 fail-soft → fail-fast trigger lands per-tool.
- M7.5 Nmap warm pool is the trigger for shipping Phase 3 (warm pool init).

**Carry-forwards to M8** (Recon-First Pipeline + Scan Type → Tool Matrix):
- WorkerConcurrency env-var configurability ready for fan-out tuning.
- errgroup adoption trigger evaluated at M8.1 scope proposal (per ADR-021 deferral).

**Carry-forwards to M9** (AI Pipeline):
- ADR-017 Option-C R2 staging trigger evaluated when ingest-time problems surface with deep-scan batches.

**Carry-forwards to OPS milestone:**
- Worker `/health` HTTP endpoint (deferred per 5.6 H.6).
- Runtime `HealthCheckLoop` per TOOL-ARCH §11.2.
- Worker-degraded marking + orchestrator-side worker-routing logic.
- Stream-key cleanup TTL (carry-forward from ADR-014).
- Per-request DB session checkout for SSE (carry-forward from M4 Task 4.4).
- Ghost-queued janitor (M4 Task 4.2 carry-forward; needed for ADR-017 sequenced-event recovery).

**Patterns established in M5** (now part of project DNA):

1. **Architectural-commitments preamble** before scope proposal — preempts integration surprise.
2. **Decision tables before conditionals** when ≥4 outcomes have distinct semantics (5.5 self-catch).
3. **Trigger-based deferral** (DEVELOPMENT-PATTERNS.md section 1).
4. **Cross-repo wire-format fixtures** (5.4 — `testdata/*.json` + `.md` provenance).
5. **Two-layer timeout** (worker shutdown + runner-internal timeout; never three).
6. **Per-job CancelSubscriber** (vs per-worker fan-out) at MVP scale.
7. **Frozen Registry** (defensive copy at construction; no mutex).
8. **Full-orchestration Execute closure** for HTTP-based runners (5.3) — asymmetric with NativeRunner's BuildArgs+ParseOutput is correct because HTTP is multi-step.
9. **Worker-lifetime services** with workerRootCtx from main (Worker, Heartbeat — 2 instances; pattern not yet promoted).
10. **runMain extraction** for testability of process-entry assembly.

**M5 health:** clean execution. Six commits, six self-catches captured, test count grew 0 → 135 with no rework or test deletion. Architectural decisions surfaced at scope-proposal time; design bugs caught by forcing functions before commit. The pattern-density of M5 (4 ADRs + DEVELOPMENT-PATTERNS.md creation + 4 self-catches across 6 tasks) reflects that this milestone built foundational infrastructure for all M6+ tool integration work.

**Ready for M6.** First task: M6.1 Nuclei. The full integration path is alive — JobConsumer.Pop → IdempotencyClaim.Claim → Registry.Get → NativeRunner.Run → CompletionsPublisher.Publish — and M6.1 is the first task that exercises it end-to-end with a real tool.

### 2026-05-01 — Task 5.5: worker processor + concurrency + cancel-watcher

**Files shipped:** `internal/worker/registry.go` (Registry, frozen at construction) · `internal/worker/processor.go` (Processor + Process method + cancel-watcher + JobDispatch translation helpers) · `internal/worker/worker.go` (Worker BRPOP loop + concurrency semaphore + WaitGroup-based graceful drain) · `internal/worker/{registry,processor,worker}_test.go` (3+13+8 = 24 tests + goleak TestMain).

**24 tests at 5.5 close** (vs planned 22 — extras were `TestProcessor_JobDispatchToTarget` + `TestProcessor_JobDispatchToScanConfig` + `TestWorker_PanicsOnInvalidConcurrency`; right-sized expansion on contract surfaces). Engine total: 110 tests across 6 packages. Race-clean, vet-clean, golangci-lint v2 reports 0 issues.

**Discrimination semantics decision table** pinned in `processor.go` Process() docstring covering the 5 outcomes from `(runErr, jobCtx.Err, ctx.Err)`. User-cancel emits `job_canceled`; worker-shutdown emits `job_completed` if Run finished cleanly before cancel arrived; tool-internal-timeout emits `job_failed` (timeout reason); other tool errors emit `job_failed` (error message). The table is the contract; the conditionals are the implementation.

**Cancel-watcher 3 exit paths verified.** `TestProcessor_CancelWatcherExitsOnJobDone` (path 1: job finished), `TestProcessor_CancelMidRun` (path 2: cancel event received), `TestProcessor_CancelWatcherExitsOnSubClose` (path 3: subscriber closed via Process's defer). goleak in TestMain verifies no leak across all paths.

**Forcing-function self-catch pattern continues.** No catch on this commit specifically — but the design surface is dense (3 files composing every prior task surface) and the discrimination semantics table forced explicit thinking that surfaced the worker-shutdown-vs-user-cancel distinction. Without articulating the table, the conditional ordering would have collapsed worker-shutdown into "cancel" semantically — which would emit `job_canceled` to Python on every worker restart, contaminating ScanJob.status semantics.

### 2026-05-01 — Task 5.5: ADR-013 retry semantics — plan §5.5 "retry up to 3x" plan-staleness

**Plan-staleness pin.** IMPLEMENTATION-PLAN.md §5.5 step 1 (line 1690) describes the test as: _"duplicate idempotency_key is silently dropped, canceled jobs don't retry, **failed jobs retry up to 3x**."_ This is stale.

**ADR-013** (Python is the sole writer for scan state) places retry/state-machine ownership on the Python re-dispatch path: when a `job_failed` event lands, M4 Python `CompletionsConsumer` updates `ScanJob.status = 'failed'`; the M5+ ghost-queued janitor (Task 4.2 carry-forward) is the canonical retry mechanism, and re-dispatch re-creates a fresh job with a new `idempotency_key`. Go-side worker has nothing to retry — it doesn't own state.

**5.5 emits `job_failed` events on tool error** and lets Python decide re-dispatch policy. No Go-side retry counter; no `max_retries` field; no exponential backoff inside Process(). The plan literal stays as written per state-at-time discipline; 5.5 implementation derives retry-ownership from ADR-013, not from plan §5.5's test description.

**Future readers** opening §5.5 expecting Go-side retry should read this DRIFT-LOG entry first.

### 2026-05-01 — Task 5.5: per-job CancelSubscriber (vs per-worker)

**Decision.** Each `Process` call spawns its own `CancelSubscriber` bound to the job's `scan_id`. N concurrent jobs = N Pub/Sub subscriptions on the engine.

**Why not per-worker.** A single worker-lifetime subscriber would need fan-out routing logic: "this `cancel_requested` event is for scan_X; which active job is processing scan_X?" That requires a registry of active jobs keyed by scan_id, with concurrent-mutation safety (job-start adds, job-end removes), with race protection against late-arriving cancel events for jobs that just completed. Per-job subscriber sidesteps all of this — each subscriber is bound to exactly one scan, lifecycle matches the job's, no fan-out needed.

**At MVP scale (5 concurrent jobs per worker)**, 5 Pub/Sub subscriptions is fine. go-redis pools connections; subscription overhead is one connection-pool slot per active subscriber.

**Trigger to revisit:** concurrency climbing to 50+ jobs simultaneously OR Redis Pub/Sub connection limits being hit in production. At that point, per-worker subscriber + fan-out routing earns its complexity.

### 2026-05-01 — Task 5.5: frozen Registry pattern

**Decision.** `internal/worker.Registry` is constructed once at worker startup (5.6 territory) with a defensive copy of the runner map. No `Set` method exposed; safe concurrent reads without mutex.

**Trade-off.** M6.8 task may extend with `Register(engine, runner)` + mutex if dynamic registration becomes needed. For M5+M6 sequential tool registration at startup, frozen-at-startup is sufficient.

**Pinned by `TestRegistry_FrozenAtConstruction`** — mutating the input map after `NewRegistry` returns does NOT affect the registry. Without this defensive copy, M6 task constructors that build the runner map and then continue to populate it would race with worker reads.

### 2026-05-01 — Task 5.5: cancel-watcher 3 exit paths

**Per-job cancel-watcher goroutine has 3 ctx-aware exit paths:**

1. `jobCtx.Done()` — job finished or canceled by another path. Watcher exits without taking action.
2. Cancel event received via `sub.Events()` — call `cancel()` on jobCtx → runner sees ctx cancel → Process emits `job_canceled`.
3. Subscriber `Events()` channel closed — Redis disconnect (per ADR-021 H.6 from 5.4: surface, don't auto-recover) OR explicit `Close()` call from Process's defer when job completes normally.

**ADR-021 Rule 2 enforced via `goleak.VerifyTestMain`** in `internal/worker` test packages. Tests `TestProcessor_CancelWatcherExitsOnJobDone` + `TestProcessor_CancelMidRun` + `TestProcessor_CancelWatcherExitsOnSubClose` collectively pin all 3 exit paths.

**Process() blocks on `<-cancelExited` in defer** before returning — synchronizes goroutine cleanup with Process return. Without this, a Process call that returns "successfully" could leave the watcher goroutine alive briefly, racing with goleak's snapshot at TestMain exit.

### 2026-05-01 — Task 5.5: discrimination semantics for runner return

**Pin.** Process() discriminates 5 outcomes from the `(runErr, jobCtx.Err, ctx.Err)` tuple. The decision table lives in code comments above Process()'s discrimination logic, exactly as drafted in the scope-proposal review.

**Why the table matters operationally.** Each emission shape maps to distinct Python-side behavior:

- **User-cancel** → `ScanJob.status = "canceled"` in Python (clear signal of user intent; UI shows "Canceled by user").
- **Worker-shutdown-cancel** → `ScanJob.status` stays "running" until Python ghost-queued janitor sweeps (signal that worker died, not user intent — re-dispatch should retry).
- **Tool-internal-timeout** → `ScanJob.status = "failed"` with timeout reason (signal that the tool ran out of time; re-dispatch with longer timeout if customer pays for it).
- **Other tool errors** → `ScanJob.status = "failed"` with error message (signal that the tool itself failed; re-dispatch may not help if it's a permanent failure).
- **Worker-shutdown-after-clean-Run** → `ScanJob.status = "completed"` (preserves the work; the cancel arrived after Run finished but before publish, and we publish anyway because the job logically succeeded).

**Future engineers** should find the decision table in the docstring and extend it when adding new outcome types, rather than reverse-engineering from conditionals.

### 2026-05-01 — Task 5.5: two-layer timeout (worker + runner)

**Pin.** Processor's `jobCtx` is just `WithCancel(workerCtx)`; runners enforce their own timeout via internal `WithTimeout(jobCtx, effective)` (5.2 NativeRunner / 5.3 DockerServiceRunner).

**Two layers** cover all real cases: worker-level shutdown propagates through `workerCtx` cancel; tool-level timeout uses runner's own `effectiveTimeout` precedence (`cfg.Timeout > runner.Timeout > default`). A third layer ("processor-internal job timeout") would add complexity without benefit — the runner already enforces the right limit.

**`cfg.Timeout` from JobDispatch** flows to `tools.ScanConfig` via `jobDispatchToScanConfig` helper. Runner respects override per its own precedence rules. Pinned by `TestProcessor_JobDispatchToScanConfig`.

### 2026-05-01 — Task 5.5: DEVELOPMENT-PATTERNS.md created (engine-side)

**Engine-side `DEVELOPMENT-PATTERNS.md`** created at 5.5. First pattern: **trigger-based deferral**.

**8+ instances cited** from across M4-M5: ADR-014 hybrid Streams+PubSub, ADR-016 Asynq scheduled scans, ADR-017 R2 staging triggers, ADR-021 errgroup adoption, 5.2 H.4 ProgressEmitter, 5.3 H.5 per-tool retry, 5.4 H.6 Pub/Sub auto-reconnect, Checkpoint 2 H.1 SSE DB-session. Triple-pin precedent satisfied many times over; promotion overdue. Landed at 5.5.

**Engine-side vs API-side.** API repo has its own `DEVELOPMENT-PATTERNS.md` in `shieldscan-docs/` (created earlier in M3 for `select_fresh` + `session_factory` DI patterns + API-key audit attribution). The two-repo docs split (Q3 Option B at Task 5.1) means each repo accumulates its own patterns; cross-cutting patterns (like trigger-based deferral, which spans both repos) are documented in whichever repo introduces the pattern's first three instances.

### 2026-05-01 — Task 5.4: Redis primitives (queue + streams + pubsub + idem)

**Files shipped:** `internal/redis/queue.go` (JobConsumer) · `internal/redis/stream.go` (ProgressPublisher per ADR-018) · `internal/redis/pubsub.go` (CancelSubscriber + CompletionsPublisher) · `internal/redis/idem.go` (IdempotencyClaim) · `internal/redis/{queue,stream,pubsub,idem}_test.go` (4+6+5+8 = 23 tests). Plus `internal/events/events.go` extended with `JobDispatch`/`JobTarget`/`JobAuth`/`JobMobileConfig`/`ProgressEvent`/`SplitForCompletion`/`DecodeJobDispatch` and `internal/events/events_test.go` extended with 6 SplitForCompletion + fixture tests. Plus 4 fixture artifacts in `internal/events/testdata/`.

**29 net-new tests at 5.4 close** (23 redis + 6 events extension). Engine total: 88 tests across 5 packages. Race-clean, vet-clean, lint-clean.

**ADR-018 file-layout discipline implemented.** Progress XADD lives in `stream.go`; cancel + completions in `pubsub.go`. Engineer adding progress logic looks at `stream.go` first; cancel/completions logic in `pubsub.go`. Plan §5.4 literal had progress in `pubsub.go` — that's the stale Pub/Sub-for-progress shape that ADR-018 corrects.

**Self-catch during TDD: caller-cancellation-vs-BRPOP-redis.Nil race.** Initial JobConsumer.Pop checked `ctx.Err()` only in the `err != nil` path, not in the `redis.Nil` (timeout) path. On real Redis where ctx-cancel mid-BRPOP can result in the BRPOP returning `redis.Nil` first (timeout) with the cancel landing right after, the cancel signal would be lost — Pop would return `(nil, nil)` instead of `(nil, ctx.Canceled)`. Caught while debugging the miniredis ctx-cancel test; restructured to check `ctx.Err()` BEFORE interpreting BRPOP's return, so the cancel signal wins regardless of BRPOP's race behavior. Pattern: ctx-error precedence over Redis-success-or-error.

### 2026-05-01 — Task 5.4: cross-repo wire-format fixtures introduced

`internal/events/testdata/` established as cross-repo contract fixture location.

**Fixtures shipped:**
- `job_dispatch_python_v1.json` — canonical SPEC §7.1 queue payload matching M4 Python `ScanQueue.dispatch` wire format.
- `job_dispatch_python_v1.md` — provenance + cross-repo update protocol.
- `job_completed_python_v1.json` — canonical SPEC §7.3 (post-ADR-017) completion event.
- `job_completed_python_v1.md` — provenance + sequencing semantics.

**Embedded via `//go:embed`** in `internal/events/events.go` as `FixtureJobDispatchPythonV1` and `FixtureJobCompletedPythonV1` byte slices. Tests in `internal/redis/` and `internal/events/` consume the embed without filesystem-relative path fragility.

**Cross-repo update protocol** (in fixture .md files): when Python emit shape changes legitimately, both fixture files AND Python emit code AND Go consumer struct must update in lockstep. The `_v1` suffix sets up versioning for future schema migrations (e.g., `_v2.json` if a breaking change ships).

**Pinned by `TestJobConsumer_MatchesPythonWireFormat`** (cross-repo wire-format test #6). DisallowUnknownFields enforces strictness — Python emit drift breaks Go decode loudly at CI time. This is the load-bearing cross-repo contract pin of Task 5.4.

### 2026-05-01 — Task 5.4: SplitForCompletion location in events package

**Decision.** ADR-017 sequencing logic placed in `internal/events/events.go::SplitForCompletion`, NOT in `internal/redis/`.

**Why.** Sequencing is contract-shaped per ADR-017 (the multi-event protocol Python's CompletionsConsumer must understand). It belongs with the type definitions for the same reason `EventSeq.Validate` does — single source of truth for what's a valid sequenced batch. Both 5.4 `CompletionsPublisher` and 5.5 processor reference `SplitForCompletion`; placing it in events package means one canonical implementation.

Future readers asking "how do JobCompletedEvents get split for sequencing?" find the answer with the type, not by tracing publisher code. Symmetry: `EventSeq` lives in events package; `SplitForCompletion` consumes/produces `EventSeq` and `JobCompletedEvent`; co-location is correct.

**Pinned by 4 SplitForCompletion tests** covering single-event boundary cases (0/1/1000 findings), multi-event sequencing (1001/2000/2500), intermediate-status override (ADR-017 partial_findings type), and authoritative-fields-on-terminal-only invariant.

### 2026-05-01 — Task 5.4: ProgressEvent as map[string]any (loose typing)

**Decision.** `events.ProgressEvent` is a type-aliased `map[string]any`, not a typed struct.

**Trade-off acknowledged.** SPEC §7.2 has 7+ event variants (`job_started`, `recon_started`, `subdomains_discovered`, `job_progress`, `finding_discovered`, `job_canceled`, `job_failed`) with payloads varying by event_type. A strict typed struct per variant would require N Go types and Go-side schema work every time Python adds a variant. Python is map-based; SPEC is the contract surface, not the Go type.

**ProgressPublisher injects** `event_type` / `scan_id` / `timestamp` headers; payload is open-ended for everything else. Symmetric with Python's `ProgressPublisher.publish(event: dict)` shape.

**Promotion path.** If type-safety pressure surfaces (specific variants need validation — e.g., `subdomains_discovered.subdomains` must be `[]string`, `job_progress.progress` must be `0-100`), promote those variants to typed structs in events package; the `ProgressEvent` map remains as fallback for variants not yet promoted. Most variants will probably never need promotion at MVP scale.

### 2026-05-01 — Task 5.4: Pub/Sub disconnect handling for CancelSubscriber

**Decision.** go-redis v9 `Subscribe` does NOT auto-reconnect on transient drops. CancelSubscriber surfaces disconnect via Events() channel close — when the underlying `pubsub.Channel()` closes (transient drop OR explicit `Close()`), the converter goroutine exits and Events() closes. Caller (M5.5 processor) detects via closed-channel receive (`_, ok := <-sub.Events(); !ok`) and decides recovery.

**Why not auto-reconnect inside the primitive.** Primitives surface failure; orchestration decides recovery. Same shape as 5.3's "retry deferred to per-tool Execute" — for CancelSubscriber, the recovery decision depends on operational context the primitive can't know (is this transient blip recoverable? Or is Redis genuinely down and we should fail-the-job?). 5.5 processor knows; 5.4 primitive doesn't.

**Subscription confirmation pattern.** `NewCancelSubscriber` calls `pubsub.Receive(ctx)` to wait for Redis's subscribe-ack before returning. Without this, a Publish emitted between `Subscribe()` and the first `Channel()` read could be lost. miniredis honors the Receive-handshake; verified by `TestCancelSubscriber_ReceivesPublishedEvent`.

### 2026-05-01 — Task 5.4: malformed-payload poison-pill protection (queue + cancel)

**Pattern applied to both JobConsumer and CancelSubscriber.** Malformed JSON payloads are dropped (queue: returns error to caller; cancel: silent skip in converter goroutine). Underlying messages are consumed (BRPOP popped; Pub/Sub delivered) so the malformed entry doesn't loop forever.

**Trade-off acknowledged.** Malformed jobs are silently lost from the customer's perspective. M4 Python orchestrator emits well-formed JSON; malformed implies upstream bug or Redis corruption. Recovery for genuine customer-impact: M5+ ghost-queued janitor (Task 4.2 carry-forward) sweeps stuck `ScanJob.status = 'running'` rows.

Alternatives rejected:
- **Re-LPUSH for retry**: risks infinite loop on persistent malformed entry.
- **Move to dead-letter list**: requires cross-repo coordination + new primitive; M4 Python doesn't have one.

Pinned by `TestJobConsumer_MalformedJSONReturnsError` (consumed-then-empty assertion) and `TestCancelSubscriber_MalformedPayloadDropped` (subscriber continues delivering valid events after garbage).

### 2026-05-01 — Task 5.4: miniredis Streams + Pub/Sub compat verified (Checkpoint 4 closure)

**Checkpoint 4 documented-confidence pin** (miniredis/v2 v2.33.0 vs go-redis/v9.7.0) verified at Task 5.4 across both Streams and Pub/Sub primitives.

**Streams** (XADD, XRANGE, XLEN, MAXLEN approximate trim) all behave per Redis spec. `TestProgressPublisher_MaxLenApplied` (publish 1500, expect `<= 1200` retained) and `TestProgressPublisher_RoundTripWithXRange` (publish then XRANGE retrieves the same payload) collectively verify.

**Pub/Sub** (Subscribe + handshake via Receive + Channel + Publish) works correctly. `TestCancelSubscriber_ReceivesPublishedEvent` verifies subscribe-handshake + per-channel routing; `TestCompletionsPublisher_RoundTripJSON` verifies cross-process event round-trip with full JSON shape preservation.

**One miniredis limitation surfaced + worked around.** miniredis's BRPOP runs synchronously and does NOT honor ctx-cancel mid-flight (real Redis cancels BRPOP via connection close + go-redis aborts). `TestJobConsumer_CtxCancelExits` works around with a short BRPOP timeout (200ms) so miniredis returns `redis.Nil` naturally; Pop's post-BRPOP `ctx.Err()` check then returns Canceled. The implementation is correct on real Redis (where mid-flight cancel IS interrupted); the test uses the short-timeout shape because miniredis can't reproduce real-Redis cancel semantics. Documented in test docstring + this DRIFT-LOG entry.

**goleak coverage** added in `internal/redis/pubsub_test.go`'s `TestMain` with `IgnoreTopFunction` for go-redis pool reaper + miniredis serve goroutine. CancelSubscriber's converter-goroutine teardown verified leak-clean across all 8 pubsub tests.

**Compat-confidence is now compat-verified.** Both engine-test deps (httpmock @ 5.3, miniredis @ 5.4) closed.

### 2026-05-01 — Task 5.3: DockerServiceRunner for HTTP-based services

**Files shipped:** `internal/tools/docker_service.go` (DockerServiceRunner + Get/Post/PollUntil/HealthCheck helpers + compile-time interface assertion) · `internal/tools/docker_service_test.go` (24 tests using httpmock v1.3.1).

**24 tests at 5.3 close** (vs planned 17). Expansion earned weight: helper-method coverage, edge cases on PollUntil (default interval, error propagation), HealthCheck variants (happy, 5xx, missing path), and the H.4-pinning ClientReusedAcrossCalls. Race-clean, vet-clean, lint-clean.

**httpmock v1.3.1 compat verified.** First real-world test of the dep that Checkpoint 4 documented as "documented-confidence, not test-verified." `httpmock.ActivateNonDefault(client)` binds correctly to per-runner HTTP clients; `t.Cleanup(httpmock.DeactivateAndReset)` provides per-test isolation. Convention `newMockClient(t)` helper in docker_service_test.go encapsulates the setup; M7 task tests reuse the same fixture pattern.

**gosec G704 suppression precedent.** Same shape as 5.2's G204 NativeRunner suppression. `HTTPClient.Do(req)` is flagged as SSRF-taint-suspicious; suppressed with explanatory `//nolint:gosec` comment because the HTTP-to-localhost-Docker-services pattern is exactly the runner's purpose. BaseURL is operator-config; paths are M7-task in-repo code; query params are Python-orchestrator-validated before dispatch.

### 2026-05-01 — Task 5.3: full-orchestration closure pattern (vs request/response split)

**Decision.** `DockerServiceRunner.Execute` is a full-orchestration closure receiving `(ctx, *DockerServiceRunner, target, cfg)`. The runner provides primitives (Get, Post, PollUntil, HealthCheck); closures compose them.

**Why not BuildRequest+ParseResponse split** (parallel to NativeRunner's BuildArgs+ParseOutput): multi-step HTTP dances cannot be expressed as a single request/response pair. ZAP's flow per TOOL-ARCH §7.2 is 5 calls (POST spider start → POLL spider status → POST active scan → POLL active scan status → GET alerts). MobSF: upload → analyze → poll → fetch report. Trivy varies by mode. SQLMap: confirm-only mode is multi-step.

**Asymmetric with NativeRunner** — and that's correct. The asymmetry reflects the underlying difference: subprocess invocation is one round-trip (args in, output out); HTTP API integration is N round-trips with per-call state. Forcing the same shape on both would either over-constrain HTTP (single-call only) or under-constrain native (multi-step orchestration that doesn't apply).

**Convention.** Execute closures treat `*DockerServiceRunner` as read-only. Mutating runner state from within Execute breaks runner reuse across jobs. Documented in DockerServiceRunner godoc.

### 2026-05-01 — Task 5.3: HTTP retry policy deferred to per-tool Execute

**Decision.** DockerServiceRunner does NOT implement HTTP retry. Each M7 tool's `Execute` closure handles retry per its own idempotency profile.

**Why generic retry would be wrong half the time:**
- **MobSF upload:** NOT retryable (re-upload creates duplicate task with new UUID).
- **MobSF status poll:** retryable (idempotent GET).
- **ZAP spider start:** NOT retryable (creates new spider job).
- **ZAP status poll:** retryable.
- **Trivy SCA:** server-side idempotent on same target; retry safe.
- **SQLMap confirm:** task creation NOT retryable; status polling retryable.

A blanket retry on `HTTPClient.Do` would either silently double-create tasks (idempotency bugs) or silently fail to retry transient errors on idempotent calls. Closure-level retry lets each M7 task ship correct semantics for its tool.

**M7 task authors** writing retry should use the existing PollUntil pattern with retry-aware predicate (treat transient 5xx as "not done yet, try again") rather than reinventing.

### 2026-05-01 — Task 5.3: HTTP client per-runner-instance for connection reuse

**Decision.** DockerServiceRunner constructs HTTP client once per runner instance (lazy via `ensureClient` on first use); reused across all Run calls and helper-method calls.

**M6.8 registry** (future) constructs each tool's runner once at worker startup; that single runner instance handles every job hitting that tool throughout the worker's lifetime. Connection pooling kicks in for repeat calls — significant for polling-heavy tools (MobSF: ~30 polls per scan; ZAP: ~100+ polls per scan; SQLMap: ~20 polls per scan). Per-call client allocation would mean N TCP handshakes + TLS negotiations per scan.

**HTTPClient.Timeout = 0.** All timeout enforcement flows through ctx (`req.WithContext(runCtx)`). Single source of truth = ctx; logical-operation timeouts don't race with client-level timeouts.

**Pinned by `TestDockerServiceRunner_ClientReusedAcrossCalls`.**

### 2026-05-01 — Task 5.3: PollUntil enforces ADR-021 Rule 2 centrally

**Decision.** `PollUntil(ctx, interval, poll)` centralizes the ctx-aware sleep pattern (`select` on `ctx.Done()` vs `time.After(interval)`). M7 closures using PollUntil inherit Rule 2 compliance automatically.

**Why this matters.** The `noctx` linter from 5.1 catches HTTP and exec violations but **not bare `time.Sleep` in polling loops**. A naive M7 task author writing `for { check(); time.Sleep(2*time.Second) }` would pass lint while silently violating ADR-021 Rule 1 (sleep ignores ctx; cancellation hangs until sleep elapses). Centralizing the pattern in PollUntil prevents M7 authors from reinventing incorrectly.

**Default interval.** When caller passes `interval <= 0`, `DefaultPollInterval = 1 * time.Second` applies. Pinned by `TestDockerServiceRunner_PollUntilDefaultInterval` (verifies interval=0 doesn't busy-loop: ~1 call in 100ms, not hundreds).

**ADR-021 Rule 2 forcing function** — first centralized helper that enforces ctx-discipline beyond the linter layer. Future M5+ patterns that would otherwise leak Rule 2 violations should follow the same "encapsulate-the-pattern" approach.

### 2026-05-01 — Task 5.2: ToolRunner interface + NativeRunner + fingerprint

**Files shipped:** `internal/tools/runner.go` (interface + Target + ScanConfig + AuthConfig types) · `internal/tools/native.go` (NativeRunner + compile-time interface assertion) · `internal/tools/fingerprint.go` (exported ComputeFingerprint) · `internal/tools/native_test.go` (16 tests + goleak TestMain) · `internal/tools/fingerprint_test.go` (3 tests).

**19 tests at 5.2 close** (vs planned 17). Two extras earned their weight: `TestNativeRunner_NilBuildArgs` and `TestNativeRunner_NilParseOutput` pin contract surface (M6 task constructors that forget to set the closures get a clear error rather than an obscure subprocess crash). All race-clean, vet-clean, lint-clean.

**Self-catch during implementation: `ExitCodeIsError` → `ExitCodeLenient` rename.** Initial design used `ExitCodeIsError bool` with the (incorrect) docstring claiming "Default (zero value, true): non-zero exit aborts Run with an error." Go's `bool` zero value is `false`, not `true` — so the field's actual default was the OPPOSITE of the documented behavior. Caught while writing tests. Renamed to `ExitCodeLenient` (zero-value=false=strict, opt-in true=lenient) so the field name + zero-value matches the dominant pattern (most native tools follow exit-zero-on-clean; gitleaks/semgrep are the minority that opt in). Cleaner shape; the user's mental model from scope-proposal review preserved.

**Pattern: forcing functions catch their own authors.** Following the 5.1 self-catch (noctx caught my own `exec.Command` violation), 5.2 added another to the pattern: **writing the test surfaced a semantic bug in the field name**. Test-first discipline isn't just for behavior — it surfaces design bugs the docstring alone wouldn't catch. Future similar moments are positive signals worth acknowledging (per user feedback after 5.1 close).

### 2026-05-01 — Task 5.2: ComputeFingerprint exported as cross-package contract

**Decision.** `ComputeFingerprint` is an exported package function in `internal/tools/`, not the lowercase `computeFingerprint` referenced in plan literal §5.2.

**Why.** M5.5 processor + future M9 AI pipeline both consume the algorithm; package-private with wrappers risks drift across consumers. The fingerprint is a contract surface (M9's primary-pass dedup key per `../shieldscan-docs/CLAUDE.md` gotcha 4); single canonical implementation is correct.

**Cross-language parity.** Any future Python computation of the same fingerprint MUST use the byte-equivalent algorithm: pipe-separated SHA-256 of `(tool_name | finding_type | target_url | parameter | code_file | code_line)` in this order. If `RawFinding.TargetURL` ever contains a literal pipe character (technically allowed in URLs but rare), collisions become possible — at that point the algorithm gets versioned and migrated, not changed in place.

### 2026-05-01 — Task 5.2: per-tool timeouts as tool-internal constants

**Decision.** `NativeRunner.Timeout` field carries per-tool default per `../shieldscan-docs/TOOL-ARCHITECTURE.md` §6 (Nuclei 30min, Subfinder 60s, etc.). `internal/config/Config` is reserved for cross-cutting tunables (worker concurrency, log level, Redis URL).

**Override path.** Job-dispatch time via `cfg.Timeout` (in `ScanConfig`) when ops tuning is needed. Effective timeout precedence: `cfg.Timeout > 0` overrides `NativeRunner.Timeout > 0` overrides `DefaultNativeTimeout` (30 min).

**Why not centralized in `Config`.** Eleven+ env vars (one per native tool) would sprawl the config struct. Most timeouts are static defaults that never need ops tuning; the few that do are exposed via `cfg.Timeout` at the job-dispatch layer.

**Pinned by `TestNativeRunner_CfgTimeoutOverride`.**

### 2026-05-01 — Task 5.2: progress emission deferred from runner interface (with explicit trigger)

**Decision.** `ToolRunner.Run(ctx, target, cfg) ([]events.RawFinding, error)` is pure compute — no progress callback. Processor (Task 5.5) emits `job_started` / `job_completed`. Mid-run progress events deferred until trigger fires.

**Trigger to add `ProgressEmitter func(EventType, map[string]any)` field to `ScanConfig`:**
- Any M6+ tool that produces meaningful intermediate state worth surfacing to the customer (e.g., Subfinder's "discovered 47 subdomains, scanning each" mid-run signal).
- Specifically NOT: tools that just take a long time silently (Nuclei's 30-minute template runs). Those don't need progress; they need a longer-status indicator on the dashboard side.

**Lean: M6.3 Recon is the likely first trigger** — Subfinder + httpx have a natural mid-pipeline boundary (subdomains discovered → httpx checks each), and TOOL-ARCH §6.3 already has `RunRecon(...publisher *ProgressPublisher)` in the plan literal.

**When trigger fires.** Add `ProgressEmitter` as an optional field in `ScanConfig`. Non-breaking — nil emitter is no-op default; production injects a real emitter via 5.5 processor; tests pass nil. This is the H.4 Option B path; deferring it now keeps 5.2's interface minimal.

### 2026-05-01 — Task 5.2: events.RawFinding supersedes plan-literal local definition

**Pin.** Plan §5.2 (lines 1577-1604) references `RawFinding` as if local to `internal/tools/`. 5.1 shipped `events.RawFinding` as part of the wire-schema package owning all SPEC §7 contract surfaces.

**5.2 imports `events.RawFinding`** rather than redefining. Single source of truth: tool runners and processor (5.5) share the exact type the wire encodes. Avoids the M6 task tax of "do I import the events one or the tools one?" — there is only one.

**Plan literal stays as written** per state-at-time discipline. M6 task authors reading §5.2 should treat the unqualified `RawFinding` as a notational shorthand for `events.RawFinding`.

### 2026-05-01 — Task 5.1: engine repo bootstrap (M5 milestone-boundary open)

**M5 — Go Worker Foundation — opens with Task 5.1 engine bootstrap.**

| Item | Detail |
|---|---|
| Repo created | `shieldscan-engine/` greenfield Go module |
| Go version | 1.26.2 (matches `../shieldscan-docs/VERSIONS.md` §2.1) |
| golangci-lint version | v2.11.4 (see entry below for v1→v2 schema choice) |
| Files in 5.1 commit | `cmd/worker/main.go` · `internal/{buildguard,config,events}/` · `.github/workflows/engine.yml` · `.golangci.yml` · README · CLAUDE.md · DRIFT-LOG.md · `.env.example` · `.gitignore` · `testdata/README.md` · go.mod / go.sum |
| Tests at 5.1 close | 16 (4 buildguard + 4 config + 8 events) — all green |
| Forcing functions wired | ADR-013 (build-graph + reflective DB-fields check) · ADR-016 (asynq exclusion) · ADR-017 (`MaxFindingsPerEvent = 1000` constant + `EventSeq` validation) · ADR-021 (goleak + go vet lostcancel + golangci-lint containedctx/noctx) |
| ADRs landed (in `../shieldscan-docs/SPECIFICATION.md` §13) | ADR-016, ADR-017, ADR-018, ADR-021 |
| Patterns established | Two-repo docs split (engine local CLAUDE/DRIFT/PATTERNS; cross-cutting in `shieldscan-docs`) · `internal/events/` as single source of wire-schema truth · `internal/buildguard/` for cross-cutting forcing-function tests |
| Carry-forwards to 5.2-5.6 | Tool runner package · Redis primitives package (split: `stream.go` for progress, `pubsub.go` for cancel/completions per ADR-018) · processor + idempotency · startup health checks · docker-compose for Layer-2 services |

**M5 health:** clean bootstrap. Linter caught one self-inflicted ADR-021 violation in the buildguard tests (`exec.Command` instead of `exec.CommandContext`) before the first commit — exactly what `noctx` is for. Refactored to `exec.CommandContext(t.Context(), ...)` and re-pinned. The ctx-discipline forcing function works.

### 2026-05-01 — Task 5.1: golangci-lint v2 schema choice

**Decision.** Engine ships with golangci-lint **v2.11.4**, not the v1.62.0 referenced in the Task 5.1 scope proposal.

**Why.** v2.x is the current upstream-stable release line as of 2026-04 (released 2025); v1.62.0 would be sticking to a stale version with no security backport guarantee. v2 has breaking config-schema changes from v1 (`version: "2"` directive, `linters.default + linters.enable` block instead of v1's enable/disable lists, `exclusions.rules` instead of `issues.exclude-rules`), so the choice is structural — `.golangci.yml` is authored against v2 schema.

**Compatibility.** All five planned linters (containedctx, noctx, errcheck, staticcheck, gosec) are available in v2. v2's `default: standard` includes errcheck + staticcheck + govet + ineffassign + unused, so we explicitly enable only the three not in standard (containedctx, noctx, gosec).

**Pinned in `../shieldscan-docs/VERSIONS.md` §2.4** alongside other engine-test deps (miniredis, httpmock, goleak).

**Carry-forward:** if golangci-lint v3 ships before M5 close, evaluate via the standard upgrade decision matrix in VERSIONS.md §4.4. v2 → v3 would likely be another schema break.

### 2026-05-01 — Task 5.1: aws-sdk-go-v2 patch bump v1.32.0 → v1.32.2

**Resolver-driven correction.** VERSIONS.md §2.4 pins `aws-sdk-go-v2 v1.32.0` and `aws-sdk-go-v2/service/s3 v1.66.0`. At engine bootstrap, `go get ...service/s3@v1.66.0` failed because s3 v1.66.0 has a hard requirement on aws-sdk-go-v2 v1.32.2. Bumped to v1.32.2.

**This is a patch-level bump within the same minor** (v1.32.0 → v1.32.2). Per VERSIONS.md §4.4, patch releases auto-upgrade. Documenting here so the bump isn't mysterious in `go.mod` vs §2.4.

**Action item:** when next refreshing VERSIONS.md §2.4, sync the aws-sdk-go-v2 pin to whatever the s3 dep requires. Or pre-resolve at update time so internal consistency holds. Low priority; the buildguard tests remain green either way.

---

*Newest first. Add entries above this line when shipping engine changes.*
