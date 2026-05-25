# shieldscan-engine — DRIFT-LOG

Engine-side design decisions, version drift, and pattern bootstraps.
Newest entries on top.

For cross-cutting decisions affecting both `shieldscan-api` and
`shieldscan-engine`, see `../shieldscan-docs/DRIFT-LOG.md`.

---

## 2026-05-25 — Task 7.4 V10 — iOS Section-Dispatch + 5 iOS Adaptors LANDED (Stage 3 Commit 2 of 3)

**Status:** Task 7.4 V10 iOS section-dispatch + 5 iOS adaptors landed at this commit (Stage 3 Commit 2 of 3 cross-repo sequencing). Partner Commit 1 (shieldscan-docs `d4f6ca7`) landed Task 7.4 design doc V10 status FORWARD_PINNED → RESOLVED; Partner Commit 3 (shieldscan-docs; forthcoming) lands Phase 5 sub-phases. V10 closes Task 7.4 final outstanding V-item (16/17 → 17/17 V-items RESOLVED).

**Authority:** V10 design doc shieldscan-docs commit `0347a79` (Y1+Y2+U1+Q1-Q7 + V-CA-V-CI + V1-V6 + Drift #45); V10 implementation plan `7c4fe75`; Task 7.4 design doc V10 status update `d4f6ca7`; Phase 0 v2 v2 empirical authorities (DVIA-v2-swift v2.0 IPA SHA256 `a0efb217f3dd018a4fbea7b2d63db7da4e21d5d7cdc20bd4a72a8a5b57e98817` + `opensecurity/mobile-security-framework-mobsf:v4.4.6` + `/tmp/v10-ios-report.json` 5.6 MB).

### Empirical Validation (Integration Test)

DVIA-v2-swift v2.0 end-to-end iOS scan via real-Docker MobSF v4.4.6: PASS in 57.88s; **169 findings** emerged with categorical distribution: ats_violation=1 (NSAllowsArbitraryLoads=true high-severity ATS bypass); dylib_protection_missing=160 (20 dylibs × ~8 sub-checks per `dylibSubChecks`); info_plist_finding=3 (NSAllowsArbitraryLoads + NSAppTransportSecurity-present + ITSAppUsesNonExemptEncryption-absent); ios_binary_finding=1 (WebView Component MSTG-CODE-9); ios_url_scheme=2 (dvia + dviaswift custom schemes flagged medium per OWASP MASVS-PLATFORM-3). All V4 baseline assertions (≥1 per finding-type) satisfied.

### Stage 3 Drift Cluster (Drifts #45-#48)

- **Drift #45** (CRITICAL pre-execution; carried-forward from Phase 0 v2 V1): iGoat-Swift refuted empirically (`assets:[]` source-only v1.0 release 2018; build requires macOS+Xcode unavailable). Pivot to DVIA-v2-swift v2.0 (OWASP-derived canonical alternative; SHA256 `a0efb217...8817`; 20.31 MB). Catch-mode: canonical-authority-of-external-resources empirical-asset-inventory.
- **Drift #46** (pre-execution static; S3C2 pre-verification V-CL): Plan §3.3 "`adaptDylibAnalysis` reuses `binarySubChecks` constant" empirically wrong. iOS dylib sub-checks `{arc, code_signature, encrypted, nx, pie, rpath, stack_canary, symbol}` vs Android `binarySubChecks` `{nx, pie, stack_canary, relocation_readonly, rpath, runpath, fortify, symbol}`: 5 overlap + 3 iOS-only + 3 Android-only. New `dylibSubChecks` constant introduced.
- **Drift #47** (pre-execution static; S3C2 pre-verification V-CO): Plan §4 C2.11 assumed mirror of existing MobSF `integration_test.go`; empirically no such file (V13+V16 was unit-test-only + manual `/tmp/` scans). Reframed as CREATION mirroring SQLMap `integration_test.go` `b48fef8` cross-package precedent.
- **Drift #48** (pre-execution static; S3C2 pre-verification V-CQ): Plan §4 C2.12 assumed `testdata/` directory existence; empirically absent. Reframed as directory creation + fixture creation; mirror approach from `sqlmap/testdata/` `b48fef8` pattern.
- **FREE drift** (favorable; V-CJ): Plan §3.2 `binary_analysis` `json.RawMessage` refactor anticipated ~5-10 LoC; empirically `adaptBinaryAnalysis` already takes `json.RawMessage`. ~0 LoC struct delta; only platform-branching at parser.go level.

### Architectural Decisions Locked

Q1 (γ) section-dispatch via platform-gated invocation in current `parseReport` (preserved single-parser-entry pattern); Q2 (a) mandatory-only 5 iOS adaptors v1 (3 empty-section forward-pinned: `macho_analysis` + `framework_analysis` + `ios_api`); Q3 (a) `binary_analysis` `json.RawMessage` + platform-conditional re-unmarshal (FREE drift; already in place); Q4 (a) V10 is 1st-instance expansion of MobSF per-section-adaptor pattern (NOT 3rd instance per Task 7.6 P5.D forward-pin; pattern stays at 2 instances MobSF+SQLMap); Q5 (a) R2 pre-signed URL pattern deferred to dedicated task; Q6 (a) ADR-017 surveillance status unchanged; Q7 (c) 3-commit cross-repo (docs status + engine implementation + docs Phase 5). Y-PLIST-PARSE (a) Go stdlib pattern-scan executed (default b pivoted at execution per dependency-add overhead vs known-key extraction simplicity); Y-INTEGRATION-TEST-SHAPE (a) single-platform iOS extension confirmed (reframed per Drift #47 as creation); Y-DRIFT-LOG-PLACEMENT (a) engine DRIFT-LOG inline at this commit.

### Per-Section Adaptor Pattern Instance State

V10 is **1st-instance expansion** of MobSF (Android+iOS internal heterogeneity within one consumer). SQLMap remains 2nd instance (2 adaptors). Pattern count stays at **2 instances**; 3rd-instance threshold per Task 7.6 P5.D + `1c6041d` canonical scope NOT triggered (V10 is internal expansion of 1st-instance MobSF; 3rd-instance would be a 3rd structurally-distinct consumer).

### Forward-Pins Preserved

- ***"Begin MobSF R2 pre-signed URL pattern task"*** — Q5 (a) re-deferral; Task 7.4 Q6.4 + ADR-015 Q5 (a) forward-pin chain settled at this V10 task body
- ***"Begin MobSF V10 iOS empty-section adaptor expansion task"*** — `adaptMachoAnalysis` + `adaptFrameworkAnalysis` + `adaptIOSAPI` when populated-state iOS testbed surfaces those sections
- ***"Resume MobSF V10 — Phase 5 sub-phases"*** — Stage 3 Commit 3 docs Phase 5 (forthcoming)
- 3rd-instance per-section-adaptor pattern evaluation (Task 7.6 P5.D forward-pin preserved; V10 doesn't trigger per Q4 (a))
- iOS adaptor v1.1+ enhancements (`info_plist` deep-parse expansion via plist library; `ats_analysis` per-policy granularity; URL scheme severity-rubric refinement)

### Cumulative Session-Tail Framing-Drift Count

48 catches at execution time across Task 7.5d + 7.1 + 7.4 + 7.5e + 7.6 + ADR-015 + Task 7.4 V10 lifecycle arc. V10 Stage 3 surfaced drifts #45-#48 (canonical-authority-of-external-resources + constant-set divergence + missing-precedent + missing-directory) + 1 FREE favorable finding (`json.RawMessage` already in place).

---

## 2026-05-24 — ADR-015 Enablement — Decrypted Credentials in Redis Transit LANDED (Stage 3 cross-repo trio complete)

**Status:** ADR-015 LANDED per shieldscan-docs commit `9a57865` (SPEC §13 ADR-015 + ADR-013/ADR-014 addendums); cross-repo enablement complete per shieldscan-api commit `742faed` (orchestrator decrypt+emit + `SCAN_CREDENTIAL_DECRYPTED` audit + positive-path tests) + this commit (SQLMap consumer cookie wiring + integration test V4 baseline upgrade). Task 4.2 deferral (`cf3b30a`) LIFTED; Task 7.6 Drift #35 architectural-reconciliation operationally CLOSED.

**Authority:** ADR-015 design doc shieldscan-docs commit `b344d0c` (Y1+Y2+Q1-Q7 brainstorming chain + V-BA through V-BI pre-verification); ADR-015 implementation plan shieldscan-docs commit `00dd2d1` (Stage 3 sub-step canonical); Stage 3 Commit 1 shieldscan-docs `9a57865`; Stage 3 Commit 2 shieldscan-api `742faed`; Task 7.6 Drift #35 forward-pin closure (shieldscan-engine commit `723426d` Phase 1 wiring-validation reframing → V4 baseline assertions at this commit); Y-DRIFTLOG-PLACEMENT (b) lock from Stage 3 Commit 1 (DRIFT-LOG entry deferred to engine commit per per-repo atomic-commit discipline).

**Empirical end-to-end validation (this commit):**

| Layer | Component | State |
|---|---|---|
| api orchestrator | `ProjectCredential` lookup via `project_id` (per-project unique) + `decrypt_credential(encrypted_data)` + emit `payload["auth"] = {type, data, fields?}` | shipped `742faed` |
| api audit | `ScanAction.SCAN_CREDENTIAL_DECRYPTED` row per credential-bearing dispatch (scan-level, not per-job per ScanAction policy) | shipped `742faed` |
| Redis transit | `JobDispatch.Auth` field carries decrypted credential for queue-residence duration; mitigations per ADR-015 §13 (TLS + authenticated access + short TTL + no-persistence config) | wire contract unchanged; populated path activated |
| worker | `jobDispatchToTarget` (line 421+) routes `JobAuth` → `target.AuthConfig` | pre-existing; consumed |
| SQLMap consumer | `buildArgs` appends `--cookie=<data>` when `target.AuthConfig.Type=="cookie"` + `Data != ""`; defensive skip for nil/non-cookie/empty | shipped this commit |
| integration test | DVWA bootstrap cookies (`PHPSESSID` + `security=low`) threaded through `Target.AuthConfig`; assertions upgraded from "0 findings (wiring-validation)" to "≥1 sql_injection + ≥1 dbms_fingerprint per V4 baseline" with per-finding CWE-89 + OWASP A03:2021 + Parameter=id + MySQL DBMS spot-checks | shipped this commit |

### Drifts Caught at Stage 3 Execution

- **#40 Y-AUDIT (b)**: api-side execution lock — extend existing `AuditLog` + `ScanAction` enum + `audit()` helper rather than create new `credential_access_audit` table per plan default (a). Reserved-enum-slot extension precedent; saved entire migration step; single audit truth source preserved.
- **#41 (CRITICAL)**: Design doc + plan pseudocode used `scan.credential_id` but `Scan` model has only `project_id`; `ProjectCredential` is per-project (unique=True per M1 invariant + Task 3.X `d4f6b1e9a527`). Linkage refined to `SELECT WHERE project_id = scan.project_id`. Pre-verification caught architectural assumption mismatch before any code written — validates verify-then-draft discipline at strongest level this multi-session arc.
- **#42 emission-site refactor**: Credential-decrypt + audit emission moved INTO `dispatch()` (after `SCAN_DISPATCHED` audit, before per-job loop) rather than inside `_build_job_payload`. `_build_job_payload(scan, job, auth_payload)` consumes pre-built dict. Single-decrypt + single-audit per dispatch; multi-job dispatches reuse same `auth_payload`. ScanAction policy "scan-level only, never per-job" cleanly satisfied.
- **#43 (latent pre-existing)**: `tests/routes/test_scans.py` `test_create_api_scan_creates_3_jobs` asserted 3 jobs but `SCAN_TYPE_TOOLS[ScanType.API]` now 4 entries (sqlmap appended in Task 7.6 `2cd4065` which missed updating this test). 2-line defensive inline fix during Stage 3 Commit 2 pytest-gate.
- **#44 (Stage 3 Commit 3 execution catch; CRITICAL operational)**: Integration test network topology mismatch. SQLMap pool containers run on default Docker bridge; `http://localhost:18080` inside SQLMap container resolves to its own loopback (NOT DVWA host-port binding). Phase 1 wiring-validation test (commit `723426d`) masked the issue by accepting "0 findings" as v1 behavior. Drift #35 closure assertions surfaced it empirically (V4 baseline assertions failed at first run with 0 findings despite operational cookie wiring). Manual debug verified argv format correct via `--network=host` SQLMap docker run reproducing V4 baseline (4 sql_injection + DBMS fingerprint). Fix: `bootstrapDVWA` extended to inspect DVWA container post-start + return bridge IP; SQLMap target URL uses `http://<dvwa-bridge-ip>:80/...` rather than `http://localhost:18080/...`. Host-port 18080 retained for test's host-side bootstrap httpClient only. Re-run with fix yielded 5 findings (4 sql_injection + 1 dbms_fingerprint) in 33.81s — V4 baseline cleanly met. Foundational architectural drift previously masked by wiring-validation assertion permissiveness.

### Y-DRIFTLOG-PLACEMENT (b) execution

Plan Stage 3 Commit 1 C1.4 originally framed DRIFT-LOG.md update as a docs-repo edit colocated with SPEC §13 landing. At Stage 3 Commit 1 execution, Y-DRIFTLOG-PLACEMENT (b) locked: defer DRIFT-LOG update to engine Commit 3 per per-repo atomic-commit discipline (avoid cross-repo single-commit-scope). This entry fulfills the deferred work.

### Architectural Decisions Locked

Q1 (a) decrypted-in-Redis-transit (orchestrator decrypts at dispatch-time; worker consumes pre-decrypted); Q2 (b) all 5 AuthType values v1 (cookie/bearer/basic/custom_header/form; SQLMap v1 cookie-only handling per consumer concern); Q3 (a) orchestrator-boundary discriminator translation (DB `auth_type` → wire `type`); Q4 (a) full ADR-013 + ADR-014 addendums + ADR-015 §13 section; Q5 (a) MobSF R2 pre-signed URL deferred to MobSF V10 task; Q6 (a) v1 audit-only (revocation forward-pinned per separate task); Q7 (a) 3-commit cross-repo (docs → api → engine; landed concretely at 9a57865 → 742faed → this commit). Y1 (b) phased scope (axes 1-4; ZAP + MobSF R2 + revocation deferred) + Y2 (β) direct Q-chain (no Phase 0 v2). Y-AUDIT (b) + Y-DRIFTLOG-PLACEMENT (b) execution-time locks per pre-verification.

### Forward-Pins Preserved

- ***"Begin credential revocation flow task"*** — Q6 (a) multi-axis territory deserving own task
- ZAP consumer cookie pass-through enablement (axis 5; consumer task; not ADR-015 scope)
- MobSF V10 task — R2 pre-signed URL pattern (Task 7.4 Q6.4 + Q5 a deferral)
- v1.1+ Redis ACL per-queue — per-tenant Redis security enhancement
- SQLMap consumer non-cookie AuthType support — bearer/basic/custom_header/form per scan-target need
- ***"Resume ADR-015 — Phase 5 sub-phases"*** — Stage 4 post-implementation cleanup
- 3rd-instance per-section-adaptor pattern evaluation (Task 7.6 P5.D forward-pin; unrelated; preserved separately)

### Cumulative Session-Tail Framing-Drift Count

44 catches at execution time across Task 7.5d + 7.1 + 7.4 + 7.5e + 7.6 + ADR-015 lifecycle arc. ADR-015 Stage 3 surfaced drifts #40-#44 (Y-AUDIT favorable infrastructure-discovery + #41 critical architectural-correctness + #42 implementation-pattern refinement + #43 latent pre-existing regression + #44 integration-test network-topology mismatch operationally masked by prior wiring-validation reframing).

---

## 2026-05-23 — Task 7.6 Phase 5.D — Per-Section Adaptor Pattern 2nd-Instance Empirical State

**Status:** Pattern at 2 instances; 3rd-instance threshold not yet reached; scope-mismatch methodology preserved.

**Authority:** Task 7.4 Phase 5.D `1c6041d` (2nd-instance evaluation criteria authority + forward-pin language); Task 7.1 Phase 5.D `aa3fb5f` (scope-mismatch methodology canonical; engine-side patterns stay out of application-side DEVELOPMENT-PATTERNS.md); shieldscan-engine commit `723426d` (Task 7.6 cross-repo pair Commit 2; SQLMap consumer Phase 1); shieldscan-api commit `2cd4065` (cross-repo pair Commit 1); shieldscan-docs commits `40606c5` (Task 7.6 plan §3.2 + §5 Phase 5.D scope) + `d8e25b5` (Task 7.6 design).

**Empirical state:** Per-section adaptor pattern reaches 2-instance state via Task 7.6 SQLMap consumer landing.

| Instance | Consumer | Location | Adaptor count |
|---|---|---|---|
| 1st | MobSF | `internal/tools/docker/service/mobsf/sections.go` | 7 adaptors (manifest + secrets + permissions + activities + receivers + services + providers section dispatchers) |
| 2nd | SQLMap | `internal/tools/docker/sqlmap/parser.go` | 2 adaptors (`adaptInjectionFindings` per-Parameter/per-technique flatten + `adaptDBMSFingerprint` discrete info finding) |

`1c6041d` forward-pin language *"per-section adaptor pattern at 1st instance via MobSF; 2nd-instance evaluation pinned to next consumer surfacing similar heterogeneous-section handling"* operationally satisfied. SQLMap parser empirically required per-section dispatch (Parameter-block injection findings + DBMS-fingerprint trailing block are structurally distinct sections of stdout; single monolithic parser would conflate semantics).

### Scope-Mismatch Methodology Preserved

Per `aa3fb5f` (Task 7.1 Phase 5.D): engine-side Go patterns (per-section adaptor heterogeneity-handling at parser layer) are out of scope for application-side `DEVELOPMENT-PATTERNS.md` (which preamble-scopes to "Python / FastAPI / SQLAlchemy / Pydantic / Redis" patterns). Document-scope test runs structurally upstream of threshold-then-duplicative test. Engine-side DRIFT-LOG tracks empirical 2-instance state without DEVELOPMENT-PATTERNS.md promotion.

### Threshold Disposition

Pattern stays at **2 instances pending 3rd-instance evaluation**. Future Phase 5.D evaluations check (a) document-scope first, (b) then threshold + duplicative-ness — per advancement of methodology in `aa3fb5f`. 3rd-instance threshold not yet reached; no canonical-document promotion territory opens at this time.

**Forward-pin trigger phrase preserved:** *"Begin Task 7.X consumer brainstorming with per-section adaptor 3rd-instance evaluation"* — triggers re-evaluation when a future DockerRunner/DockerServiceRunner consumer surfaces similar per-section heterogeneity (likely ZAP-active Phase 1 or future API-fuzzing tool). At 3rd-instance reach, supplementary findings (signature divergence between 1st + 2nd + 3rd; unified-form viability assessment) get catalogued before final promotion/decline disposition.

**Verdict:** No engine package code change; no canonical-document promotion; SQLMap `adaptInjectionFindings` + `adaptDBMSFingerprint` stay at `sqlmap/parser.go` per Task 7.6 design d8e25b5 §4 Q2 (a) lock; MobSF `sections.go` 7 adaptors stay at canonical 1st-instance location; pattern documentation lives in this DRIFT-LOG entry pending 3rd-instance threshold reach.

---

## 2026-05-19 — Task 7.1 Phase 5.D — C-Pattern Severity-Normalization Evaluation (OUTCOME γ-honest)

**Status:** Evaluated; **OUTCOME γ-honest — promotion DECLINED on dominant scope-mismatch rationale**; 1c6041d's not-duplicative criterion supplemented (not replaced) by scope-mismatch finding.

**Authority:** Task 7.4 Phase 5.D `1c6041d` canonical scope (3-instance threshold criteria + forward-pin language for Trivy as 3rd M7 instance); Task 7.1 Phase 5 pre-verification surface report this session (V-K canonical scope verification + V-L 3-helper signature comparison + V-M DEVELOPMENT-PATTERNS.md scope-mismatch finding); shieldscan-engine commit `d4028d0` (Task 7.1 Phase 1 close; `mapTrivySeverity` 3rd M7 instance live); shieldscan-docs commit `ce7d48b` (Task 7.1 Phase 5.A design doc drift annotations); shieldscan-docs commit `c2445b9` (Task 7.1 Phase 5.C SPEC §3.2 directory layout annotation).

**Evaluation scope:** `1c6041d` canonical threshold language: *"severity normalization helper at 2 instances — ZAP + MobSF — ARE candidates for future DEVELOPMENT-PATTERNS entries IF they reach 3-instance threshold via Trivy (Task 7.1) and/or SQLMap (Task 7.6) consumer tasks."* Task 7.1 `mapTrivySeverity` ships in Phase 1 at `internal/tools/docker/trivy/parser.go` line 193 — 3rd M7 instance live. Pre-Phase-5.D framing: threshold MET; promotion question opens.

### Per-Finding Analysis

**Finding 1 — Threshold formally MET.** `mapZAPRisk` (`service/zap/parser.go:85`) + `mapMobSFSeverity` (`service/mobsf/parser.go:77`) + `mapTrivySeverity` (`docker/trivy/parser.go:193`) = 3 M7 DockerServiceRunner/DockerRunner consumer instances. `1c6041d` canonical 3-instance threshold criterion satisfied per its own framing.

**Finding 2 — Signature divergence (domain-driven; weakens unified-form promotion).** Helper shapes:

| Helper | Signature | Drop semantics |
|---|---|---|
| `mapZAPRisk` | `(risk string) (severity, drop bool)` | YES — drops `"False Positive"` + `""` |
| `mapMobSFSeverity` | `(sev string) (severity, drop bool)` | YES — drops `""`, `"secure"`, `"good"` |
| `mapTrivySeverity` | `(severity string) string` | NO — `UNKNOWN`/empty → `"info"` defensive |

Trivy genuinely lacks sentinel-filter use cases (Trivy emits real CVE findings; no `"secure"`/`"False Positive"`/`"good"` markers to filter). This is domain-driven divergence, not implementation drift. If pattern promoted, would require explicit "drop-bool optional per consumer-domain" caveat. Argues against single-canonical-form promotion.

**Finding 3 — DOMINANT: DEVELOPMENT-PATTERNS.md scope mismatch.** Pre-verification V-M finding: DEVELOPMENT-PATTERNS.md preamble line 5 explicitly states *"Scope: Application-side patterns (Python / FastAPI / SQLAlchemy / Pydantic / Redis)."* All 3 existing entries (SQLAlchemy Identity-Map Staleness; Long-lived Background Tasks; API-key Audit Attribution) are application-side Python/SQLAlchemy patterns. Engine-side Go patterns are EXPLICITLY OUT OF SCOPE per preamble. Severity-normalization helpers (`mapZAPRisk` + `mapMobSFSeverity` + `mapTrivySeverity`) are engine-side Go patterns. **Document scope mismatch is the dominant rationale against promotion regardless of instance count.**

### Methodology Advancement on `1c6041d`

Task 7.4 Phase 5.D `1c6041d` cited "not-duplicative" criterion as rationale for declining promotion. Task 7.4 evaluation sidestepped the document-scope question; promotion was correctly declined but the scope-mismatch finding was implicit (not surfaced). Task 7.1 Phase 5.D surfaces the scope-mismatch finding explicitly.

**Methodology evolution:** Future Phase 5.D evaluations should check document-scope first, then threshold + duplicative-ness criteria. *"Does this pattern belong in this document at all?"* is structurally upstream of *"Has the pattern reached threshold?"* Engine-side patterns surfaced during M7+ consumer implementations don't pass the threshold-then-scope test; they fail the scope test before threshold becomes relevant.

`1c6041d` framing remains preserved as authoritative for its decision context. This entry doesn't invalidate `1c6041d`; it supplements with the additional rationale that `1c6041d` sidestepped. Both findings hold: not-duplicative AND scope-mismatch both decline promotion.

### Verdict

**OUTCOME γ-honest — promotion DECLINED on dominant scope-mismatch rationale.** `mapTrivySeverity` stays at `internal/tools/docker/trivy/parser.go`; no DEVELOPMENT-PATTERNS.md entry created; canonical lowercase output set preserved per ZAP/MobSF/Trivy convergent convention (no document promotion needed for convention persistence).

### Forward-Pins

1. **Engine-side patterns document evaluation** — IF engine-side Go patterns warrant their own canonical document (e.g., `DEVELOPMENT-PATTERNS-ENGINE.md` OR scope-expansion of existing `DEVELOPMENT-PATTERNS.md`), re-evaluate severity-normalization promotion at that scope decision. Trigger phrase: ***"Begin engine-side DEVELOPMENT-PATTERNS document scope evaluation task"***.
2. **Signature divergence resolution** — IF future M7 consumer (e.g., SQLMap Task 7.6) surfaces 4th severity-normalization helper, evaluate whether drop-bool semantics converge OR remain domain-driven. Signature unification may become possible (or remain genuinely divergent) at 4-instance threshold.
3. **Per-section adaptor 2nd-instance evaluation** — preserved per `1c6041d` canonical scope language; pattern stays 1-instance (MobSF only) per Task 7.4 Phase 0 v2 V13/V16 verification (uniform-shape tracker section per MobSF + uniform Results[] per Trivy Q7 lock). Continues to SQLMap Task 7.6 as 2nd-instance trigger if applicable.
4. **Mobile-evidence typed-field cluster 2nd-instance evaluation** — preserved per `1c6041d` canonical scope; stays 1-instance (MobSF only) per Task 7.1 Phase 1 (Trivy is SCA + container; not mobile-evidence territory). Continues to future mobile-consumer tasks as 2nd-instance trigger.

### Cross-References

- shieldscan-engine commits: `1c6041d` (Task 7.4 Phase 5.D canonical 3-instance threshold framing authority); `d4028d0` (Task 7.1 Phase 1 close; `mapTrivySeverity` 3rd M7 instance live); `d31b831` (Task 7.4 Phase 0 v2 D.2; latest engine state pre-P5.D)
- shieldscan-docs commits: `ce7d48b` (Task 7.1 Phase 5.A design doc drift annotations); `c2445b9` (Task 7.1 Phase 5.C SPEC §3.2 directory layout annotation; latest docs state pre-P5.D)
- DEVELOPMENT-PATTERNS.md preamble line 5 (Application-side scope explicit; engine-side out of scope)
- `internal/tools/docker/service/zap/parser.go:85` (`mapZAPRisk` 1st M7 instance)
- `internal/tools/docker/service/mobsf/parser.go:77` (`mapMobSFSeverity` 2nd M7 instance)
- `internal/tools/docker/trivy/parser.go:193` (`mapTrivySeverity` 3rd M7 instance)

---

## 2026-05-17 — Task 7.4 Phase 0 v2 — V13 + V16 Empirical Verification (RESOLVED)

**Status:** Executed; **PRIMARY OUTCOME α: V13 + V16 RESOLVED via empirical verification**; 16 of 17 design-doc V-items now RESOLVED; 1 (V10 iOS section-name variance) FORWARD_PINNED for separate task.

**Authority:** shieldscan-docs commit cd933c5 (Task 7.4 Phase 0 v2 D.1 design-doc annotation; V13/V16 RESOLVED + summary line update + V10 forward-pin preserved; cross-repo pair D.1 partner); Task 7.4 design doc shieldscan-docs commit 02be8cf (V10/V13/V16 forward-pin canonical authority; lines 236–246); Task 7.5d D.2 cross-repo pair DRIFT-LOG entry precedent at engine commit 18e120f (Placement α newest-first; subsection format); Phase 0 v2 surface reports this session capture full empirical evidence chain (Phase A setup + Phase B per-V-item scans + Phase C verdict-lock + Phase D.1 docs annotation + this D.2 engine commit).

**Verification scope:** V13 (`network_security` populated-state shape verification) + V16 (`trackers` populated-state shape verification); Path α per Q1 lock (Android-only; V10 iOS excluded as separate testbed-axis; forward-pinned with refined testbed candidate iGoat-Swift).

**Testbeds:** DuckDuckGo Android 5.279.1 (SHA256 `a5ffbd14c9d9f123d2609455749900eea46079ad0328e11ca944c69f9bf38502`; 126.5 MB) → V13 populated-state source (4 `network_findings`); InsecureBankv2 (SHA256 `b18af2a0e44d7634bbcdf93664d9c78a2695e050393fcfbb5e8b91f902d194a4`; 3.46 MB) → V16 populated-state source (3 trackers). MobSF v4.4.6 pinned digest reused per Task 7.4 V1 (`sha256:72311e3553ca2c21043923cace27ed99f800cd641e9368160406779516dd774e`).

### Per-V-Item Verdicts

| V-Item | Verdict | Source | Refinement |
|---|---|---|---|
| V13 `network_security` | FIELD_NAMES_ACCURATE + TYPE_DRIFT_MINOR | DDG `/tmp/ddg-scan.json` | `scope` `[]string` vs parser `string` assertion → `coerceScope` list→string helper in `adaptNetworkSecurity`; `scope_list` Metadata key preserves raw shape per ADR-027 |
| V16 `trackers` | FIELD_NAMES_ACCURATE + ENRICHMENT_OPPORTUNITY | IBv2 `/tmp/ibv2-scan.json` | `categories` + `url` high-value fields not previously captured → `tracker_categories` + `tracker_url` Metadata keys added (omit-when-empty per ADR-027) |

**Cumulative Outcome — V13 + V16 forward-pin CLOSURE via Phase D bounded refinement.** ADR-008 amendment territory N/A (no architectural commitment shift; bounded parser field-handling refinement).

### Architectural Insight — Testbed-Inversion Methodology Learning

Pre-Phase-A hypothesis: InsecureBankv2 → V13 populated (custom NSC XML); DuckDuckGo → V16 populated (privacy-focused with some tracker telemetry).

Empirical reality inverted: DDG → V13 (4 populated `network_findings`); IBv2 → V16 (3 populated trackers: Google AdMob + Google Analytics + Google Tag Manager); DDG V16 was 0 trackers (privacy-design-intent match); IBv2 V13 was 0 `network_findings` (NSC absent or incompatible schema). Both V-items still populated; testbeds cross-covered each other.

**Methodology lesson:** Single-testbed strategy would have produced false-empty V13 conclusion (if only IBv2 chosen, V13 still appears unpopulated; would have closed V13 as ENDPOINT_ABSENT / SHAPE_UNDETERMINED instead of FIELD_NAMES_ACCURATE + TYPE_DRIFT). **Dual-testbed cross-validation caught the false-empty risk that pre-hypothesis-driven single selection would have missed.**

**Pattern analogy:** Mirrors Task 7.5d F1 (schema-level architectural boundary; surfaced via direct empirical inspection rather than predicted) + Task 7.5c V4 §11.5 architectural-insight precedent (empirical methodology reveals what hypothesis-driven analysis cannot).

**Methodology learning forward-pin for future Phase 0 v2 work:** Dual-testbed cross-validation is canonical methodology against false-empty pre-hypothesis-driven conclusions; single-testbed approaches risk false-negative findings driven by APK selection assumptions. Pattern candidate for DEVELOPMENT-PATTERNS evaluation if 2nd cross-validation instance surfaces in future task.

### Refinement Summary

**`internal/tools/docker/service/mobsf/sections.go` changes:**

- `adaptNetworkSecurity` (V13): `coerceScope` helper added (string + `[]any` + nil cases); list→string coercion for Title population; `scope_list` Metadata key preserves raw `scope` JSON shape per ADR-027 snake_case + omit-when-empty conventions
- `adaptTrackers` (V16): `tracker_categories` + `tracker_url` Metadata keys added (omit-when-empty per ADR-027) per Phase B B.6 ENRICHMENT_OPPORTUNITY
- `forward_pin_v13` + `forward_pin_v16` breadcrumb language: `"shape not yet stabilized in v4.x"` → `"verified against v4.4.6 reality (Phase 0 v2; shieldscan-docs cd933c5)"`

**`internal/tools/docker/service/mobsf/sections_test.go` additions:**

- `TestAdaptNetworkSecurity_V4_4_6_ScopeList` — covers `[]any` scope coercion + multi-element join + `scope_list` Metadata + breadcrumb update assertion
- `TestAdaptTrackers_V4_4_6_Enrichment` — covers `tracker_categories` + `tracker_url` Metadata population + omit-when-empty discipline + breadcrumb update assertion
- Pre-existing `*_PopulatedForwardPin` tests preserved (string-scope back-compat coverage)

**No SPEC revision; no ADR amendment; no other consumer changes; no shieldscan-api commit.**

### Forward-Pins

1. **V10 iOS section-name variance** — PRESERVED with refined testbed candidate iGoat-Swift; trigger phrase: ***"Begin MobSF V10 iOS verification + section-dispatch task"***
2. **V13 `network_summary` capture** — FORWARD_PINNED to v1.x informational summary work (processor-level severity rollup capability)
3. **V16 `detected_trackers` + `total_trackers` counters** — FORWARD_PINNED (same v1.x scope as #2)
4. **Per-section adaptor pattern 2nd-instance evaluation** — Phase 5.D 1c6041d V5.E.1 forward-pin maintained; trackers section heterogeneity NOT surfaced (uniform per-tracker shape); pattern continues to SQLMap Task 7.6 as 2nd-instance trigger
5. **Testbed-inversion methodology learning** — FORWARD_PIN: future Phase 0 v2 sessions reference dual-testbed-cross-validation as canonical methodology; DEVELOPMENT-PATTERNS evaluation candidate if 2nd instance surfaces

### Cross-References

- shieldscan-docs commits: `cd933c5` (Phase D.1 design-doc annotation; this commit's cross-repo pair partner); `02be8cf` (Task 7.4 design doc canonical authority); `8a72467` (Task 7.1 filename correction; latest state pre-D.1); `575ed1f` (Task 7.5d D.1 docs annotation precedent for D.1+D.2 cross-repo pattern)
- shieldscan-engine commits: `18e120f` (Task 7.5d Phase D.2 DRIFT-LOG entry shape precedent + Placement α convention); `c15a60d` (Task 7.4 MobSF consumer; V10/V13/V16 forward-pin origin in original DRIFT-LOG entry); `1c6041d` (Task 7.4 Phase 5.D C-pattern forward-pin canonical authority; per-section adaptor V5.E.1 reference)
- shieldscan-api commit: `6403a3f` (Task 7.4 D-PLAN-7 orchestrator default; unaffected by Phase 0 v2 refinement)
- SPEC §13 ADR-027 (RawFinding.Metadata schema; snake_case + omit-when-empty conventions; canonical authority for `scope_list` + `tracker_categories` + `tracker_url` keys)
- MobSF source: `home.py` (delete_scan implementation); StaticAnalyzer schema (suppressfindings + scan tables); v4.4.6 pinned at `sha256:72311e3553ca2c21043923cace27ed99f800cd641e9368160406779516dd774e`
- Phase 0 v2 testbeds: `/tmp/diva-beta.apk` (control baseline; preserved); `/tmp/InsecureBankv2.apk` (V16 source); `/tmp/exodus-testbed.apk` (V13 source; DDG 5.279.1)

---

## 2026-05-16 — Task 7.5d MobSF Cleanup Contract Verification (Empirical Execution)

**Status:** Executed; **PRIMARY VERDICT: RECOMMEND RETAIN `cfg.EphemeralContainer = true`**; **SECONDARY VERDICT: CLEAN** (no version drift).

**Authority:** shieldscan-docs commit 575ed1f (Task 7.5d plan §11 verification
execution record); shieldscan-docs commits 3579131 + 1455449 (plan landing +
date correction); shieldscan-docs commit eab7572 (Task 7.4 Phase 5.B ADR-008
ephemeral-default amendment; flip-condition canonical authority empirically
strengthened by this verification); Task 7.5d plan at
`plans/2026-05-16-task-7.5d-mobsf-cleanup-verification-plan.md` (Q1-Q9
brainstorming chain + Phase A+B+C+D structure); Task 7.5c V4 Phase D.3
precedent at shieldscan-engine commit bfccef8 (DRIFT-LOG entry shape +
methodology precedent).

**Scope.** Empirical verification of MobSF `delete_scan` cleanup contract
against pinned MobSF digest
`sha256:72311e3553ca2c21043923cace27ed99f800cd641e9368160406779516dd774e`
(v4.4.6). Executed against DIVA APK testbed reused from Task 7.4 Phase 0
(`/tmp/diva-beta.apk`; SHA256 `da829be1...`). 7 surfaces tested (S1-S3
source-code-known revalidation + S4-S7 V5-UNCLEAR per ADR-008 flip
conditions) + 4 IF tests. Hybrid Phase B per Option γ (S4 schema-locked
NOT_RESET pre-determined at Phase A source-code reading; empirical cycle
skipped as zero-information-add for S4). NO engine code changes;
verification confirms Task 7.4 Q5 ephemeral lock is empirically correct.

### Per-Surface Verdicts

| Surface | Verdict | Note |
|---|---|---|
| S1 uploads dir | ✅ RESET_COMPLETE | hash dir + apktool extraction → 0 entries |
| S2 StaticAnalyzer\* DB tables | ✅ RESET_COMPLETE | row → 0 rows (Android/iOS/Windows/EnqueuedTask) |
| S3 RecentScansDB | ✅ RESET_COMPLETE | row → 0 rows |
| S3 downloads artifacts | ✅ RESET_COMPLETE | hash-prefix files → 0 |
| S4 Suppression registry | ⚠️ NOT_RESET | Schema-locked (source-code authority); `StaticAnalyzer_suppressfindings` PACKAGE_NAME-scoped; cannot intersect MD5-scoped `delete_scan` |
| S5 User accounts | ⚠️ FAILED_TO_VERIFY | REST API absent; only Django web admin endpoints (`/users/`, `/create_user/`, `/delete_user/`) non-REST |
| S6 Instance settings | ⚠️ FAILED_TO_VERIFY | `/api/v1/settings` + `/api/v1/config` both 404 |
| S7 Plugin tuning | ⚠️ FAILED_TO_VERIFY | `/api/v1/scan_config` 404; surface may not exist as REST-managed state in v4.4.6 |

### Idempotency + Failure Mode Tests

- **IF1** (idempotent `delete_scan` on already-deleted + never-existed hashes): ✅ Both return `{"deleted": "Scan not found in Database"}` STATUS=200; caller cannot distinguish — non-fatal
- **IF2** (mid-scan `delete_scan`): ⚠️ **BONUS FINDING F2** — HTTP 500 + `[Errno 39] Directory not empty` filesystem race; partial-cleanup orphan state (RecentScansDB wiped but StaticAnalyzerAndroid + uploads dir remain); orphan `delete_scan`-uncleanable through REST API
- **IF3** (invalid + no auth): ✅ Both 401 `{"error": "You are unauthorized..."}` — uniform single-key auth
- **IF4** (partial-upload): ✅ 400 `{"error": "File format not Supported!"}` on 10KB zero file; clean rejection with no orphan filesystem state from rejection

### Cumulative Verdict

**RECOMMEND RETAIN `cfg.EphemeralContainer = true` for MobSF.** Per ADR-008
amendment strict conformance (shieldscan-docs commit eab7572 lines 1206-1208):
*"RECOMMEND FLIP if and only if ALL 4 surfaces (S4 + S5 + S6 + S7) verify
RESET_COMPLETE; RECOMMEND RETAIN if ANY S4-S7 verifies PARTIAL_RESET /
NOT_RESET / FAILED_TO_VERIFY."* Empirical: 4-of-4 S4-S7 surfaces fail
RESET_COMPLETE bar (S4 NOT_RESET schema-locked; S5/S6/S7 FAILED_TO_VERIFY
REST API absent). ADR-008 amendment empirically strengthened; ephemeral
default architecturally correct (NOT transitional).

**Secondary verdict — CLEAN (no version drift):** S1-S3 all RESET_COMPLETE
empirically confirmed at v4.4.6 pinned digest; source-code predictions from
Task 7.5b V5 reading hold at runtime.

### Finding F1 — Configuration-State Cleanup Architectural Boundary

MobSF v4.4.6 `delete_scan` cleanup contract is fundamentally hash-scoped
(per-scan); configuration-scoped state is structurally outside `delete_scan`'s
authority.

(a) **S4 suppression registry — schema-locked architectural boundary:**
`StaticAnalyzer_suppressfindings` primary association is `PACKAGE_NAME`
(varchar 260); `delete_scan` operates on MD5 hash; schema design prevents
intersection even hypothetically. Source-code `home.py:537-587` verified —
`delete_scan` never touches `suppressfindings` table.

(b) **S5-S7 REST API completeness gap:** S5 users only Django web admin
endpoints (`/users/`, `/create_user/`, `/delete_user/`) admin-cookie-gated;
non-REST. S6 settings: no REST representation (`/api/v1/settings` +
`/api/v1/config` both 404). S7 plugin tuning: no REST representation
(`/api/v1/scan_config` 404; surface may not exist as REST-managed state
in v4.4.6).

**Finding shape stronger than Task 7.5c V4's ZAP `newSession`
documentation-gap finding (engine commit bfccef8 §11.5):** MobSF's boundary
is schema design choice + REST API completeness gap; not a documentation
defect. The architectural boundary is empirically inherent to v4.4.6.

### Finding F2 — Sync-Mode `delete_scan` Race Condition Producing Uncleanable Orphan State

Mid-scan `delete_scan` in sync mode (v1 engine default per Task 7.4 Q4 lock;
orchestrator default at shieldscan-api commit 6403a3f) produces partial-cleanup
orphan state `delete_scan` itself cannot remediate through REST API.

**Root cause:** Source-code `home.py:549-559` guards *"scan can only be deleted
after it is completed"* rejection on `settings.ASYNC_ANALYSIS=true` AND
`EnqueuedTask` row existence; in sync mode neither holds; `delete_scan`
proceeds and races still-running scan's filesystem mutations.

**Empirical observation (Phase B.3):** HTTP 500 + `[Errno 39] Directory not
empty` error; RecentScansDB wiped (mid-scan delete partially succeeded);
StaticAnalyzerAndroid row remains as orphan; uploads dir remains as orphan.

**Recovery path infeasibility:** Follow-up `delete_scan` returns *"Scan not
found in Database"* because `home.py:547` `RecentScansDB.objects.filter(MD5=md5_hash).exists()`
short-circuits before touching orphan StaticAnalyzer row + uploads dir.
Orphan is `delete_scan`-uncleanable through REST API.

**Operational implication for engine consumer:** Same-tenant warm-pool
retention path (if ever implemented) requires defensive code handling
sync-mode race OR `MOBSF_ASYNC_ANALYSIS=1` mode adoption. Reinforces RETAIN
verdict from second independent angle.

**No engine code action this commit.** F2 establishes new forward-pin
territory (engine defensive code OR ASYNC_ANALYSIS=1 evaluation); v1
sync-mode operation continues as-is for current scope (ephemeral container
default means orphan state is destroyed with container teardown; F2 only
materializes operationally under warm-pool retention or persistent-service
consumer topology).

### Phase D Disposition

**No SPEC revision required.** ADR-008 amendment text (eab7572) *"Until then,
ephemeral is the architecturally-correct default (NOT transitional)"* is
empirically strengthened by F1 + F2; addendum stays canonical. §14.1 row 7
(ADR-008 invocation enumeration) stays unchanged.

**No engine code flip.** `cfg.EphemeralContainer = true` (per Task 7.4
c15a60d) preserved as architecturally-correct default; F1 + F2 reinforce
this default's correctness.

**No shieldscan-api commit.** RETAIN outcome doesn't affect orchestrator;
default `analysis_type="static"` at 6403a3f stays canonical.

**Phase D commit pair:** D.1 shieldscan-docs commit 575ed1f (plan §11
verification execution record); D.2 this commit (engine DRIFT-LOG entry).
Independent commits per repo (no cross-repo coordinated commit pair pattern
needed; different artifact scopes).

### Forward-Pins (Post-Execution)

1. **MobSF v5+ API surface re-evaluation** — if future MobSF versions expose
   REST API for S5/S6/S7 surfaces OR if v5+ redesigns schema-level
   architectural boundary affecting S4, re-execute Task 7.5d verification at
   new pinned digest.
2. **F2 sync-mode race condition remediation** — engine defensive code
   (best-effort `delete_scan` with orphan-recovery handling) OR
   `MOBSF_ASYNC_ANALYSIS=1` mode adoption evaluation; forward-pinned as
   future-task territory if warm-pool retention is ever reconsidered OR if
   sync-mode race surfaces operationally.
3. **F1 schema-level boundary upstream contribution** — community
   contribution opportunity (analogous to Task 7.5c V4 ZAP documentation MR
   forward-pin per bfccef8 §11.8); upstream MobSF API/schema redesign would
   be required for any cleanup contract reaching V5-UNCLEAR surfaces.
4. **iOS section variance + V13/V16 populated-state shape** — Task 7.4
   V10/V13/V16 forward-pins preserved; separate Phase 0 v2 scope.

### Cross-References

- shieldscan-docs commits: 575ed1f (Phase D.1 plan §11 annotation); 3579131
  (Task 7.5d plan date correction); 1455449 (Task 7.5d plan landing);
  eab7572 (Task 7.4 Phase 5.B ADR-008 amendment; empirically strengthened by
  this verification); 124f5aa (Task 7.5c V4 Phase D.1 plan §11 precedent);
  3067c92 (Task 7.5b V5 forward-pin source)
- shieldscan-engine commits: 1c6041d (Task 7.4 Phase 5.D close); c15a60d
  (Task 7.4 MobSF consumer; Q5 ephemeral lock authority); bfccef8
  (Task 7.5c V4 Phase D.3 engine DRIFT-LOG precedent + methodology)
- shieldscan-api commit: 6403a3f (Task 7.4 D-PLAN-7 orchestrator default
  `analysis_type="static"`; sync-mode default per Q4 lock)
- Source-code authority: MobSF v4.4.6 `home.py:537-587` (`delete_scan`
  implementation); `home.py:547` (RecentScansDB existence check; orphan
  recovery short-circuit); `home.py:549-559` (ASYNC_ANALYSIS rejection
  guard); `StaticAnalyzer_suppressfindings` schema (PACKAGE_NAME primary
  association)
- SPEC sections: §13 ADR-008 (amendment; eab7572 lines 1198-1210;
  ephemeral-default canonical); §14.1 row 7 (ADR-008 invocation
  enumeration); ADR-026 (DockerServiceRunner framework); ADR-027
  (RawFinding.Metadata canonical)

---

## 2026-05-10 — Task 7.4 MobSF Consumer (MAST) — Phase 1+Phase 4 Adjunct

**Authority:** `plans/2026-05-09-task-7.4-mobsf-consumer-design.md` (commit
02be8cf in shieldscan-docs); `plans/2026-05-09-task-7.4-mobsf-consumer-implementation.md`
(commit 4a94c2e).

**Scope:** Second DockerServiceRunner consumer (after Task 7.3 ZAP). MAST
(Mobile Application Security Testing) via MobSF v4.4.6 at pinned digest
`sha256:72311e3553ca2c21043923cace27ed99f800cd641e9368160406779516dd774e`.
Static analysis only v1 per Q1 lock. Ephemeral container architecture per
Q5 lock (mirroring Task 7.5b V4 Option γ for ZAP); Task 7.5d delete_scan
cleanup verification forward-pinned.

**Phase 0 Empirical Verification (6+ drifts surfaced + auto-corrected in Phase 1):**

- D1 files-dict shape (`map[path]string` CSV, not list-of-structured-objects)
- D2 metadata.ref key (3-letter; not "reference")
- D3 owasp-mobile colon format ("M7: Client Code Quality"; not hyphen)
- D4 masvs full canonical form ("MSTG-STORAGE-2"; not "code-8" short form)
- V5 severity lowercase ("high"/"warning"/"info"; not uppercase)
- V17 certificate_findings list-of-3-element-lists (`[[severity, title, description]]`; not objects)
- V8 decision-lock: rule_id → Title directly (snake_case human-readable per DIVA sample)

**Phase 1 Implementation:**

- 8 prod files + 7 test files at `internal/tools/docker/service/mobsf/`
  (1,323 LoC prod + 1,161 LoC tests = 2,484 LoC delta)
- Q3 lock: MobSF removed from `deploy/docker-compose.services.yml` +
  `deploy/docker_compose_test.go` assertions
- AWS SDK Go v2 added to `go.mod` for R2 S3-compatible client
  (consumer-local; Q6.1 lock)
- Coverage 82.3% (target ≥80%); 24+1 = 25 packages green; lint clean

**Phase 1 D-Deviations (6 total; all auto-corrected with disposition):**

- D-PLAN-1 R2 env-var naming: auto-corrected to `SHIELDSCAN_R2_*`
  config-injection pattern (matches engine config layering; aligns with
  `internal/config/config.go` convention)
- D-PLAN-2 ScanConfig mobile fields: ExtraArgs escape-hatch v1
  (`mobsf.platform` / `mobsf.analysis_type`); processor wiring landed in
  Phase 4 adjunct (this commit)
- D-PLAN-3 AWS SDK `BaseEndpoint` over `EndpointResolverV2`
  (idiomatic R2; simpler)
- D-PLAN-4 parser/sections LoC over-estimate (V14 binary 8-sub-check fan-out
  + V13/V16 forward-pin scaffolding)
- D-PLAN-5 gosec `//nolint` annotations (3 places; all scoped + explained)
- D-PLAN-6 AWS SDK transitive pin addendum: forward-pinned to Phase 5.A
  docs followup

**Phase 2 Cross-Repo Verification:**

- shieldscan-api mobile infrastructure INTACT (V2.1-V2.3 + V2.5 + V2.6 all
  clean per V6 finding)
- V2.4 surfaced wire-deserialization gap: `processor.jobDispatchToTarget`
  dropped Platform + AnalysisType on the floor; only UploadRef populated;
  `ScanConfig.ExtraArgs` had no mobile mirror
- D-PLAN-2 final disposition: Path Y (ExtraArgs preserved as v1 path);
  processor wiring as Phase 4 adjunct (this commit) — 6-LoC mirror + 39-LoC
  test in `internal/worker/processor.go`

**Phase 2 New D-Deviation Surfaced + Resolved:**

- D-PLAN-7 orchestrator default "both"→"static" mismatch: Path (c) flip
  orchestrator default at shieldscan-api boundary (cleanest cross-repo
  contract; breaks OUTCOME b purity intentionally to address real
  mismatch); shieldscan-api companion commit lands this fix

**Architectural Insight:**

Phase 2 surfaced first cross-repo coordination need of session-tail.
Task 7.4 ships as cross-repo coordinated commit pair (api FIRST → engine
SECOND with cross-reference). Task 7.3 + 7.5c were single-repo. Pattern:
cross-repo coordination warranted when verification surfaces real
contract mismatches; single-repo discipline preserved when no contract
mismatch exists.

**Security Implication:**

Q5 ephemeral lock per Task 7.5c V4 precedent: bounded ephemeral startup
cost vs unbounded cleanup-contract-uncertainty risk. MobSF V5 forward-pin
("Suppression/user/settings UNCLEAR") matches ZAP pattern that Task 7.5c
empirically falsified. Task 7.5d empirical verification of delete_scan
cleanup contract is forward-pinned; until then, ephemeral is
architecturally correct (not transitional).

**Forward-Pins (Future-Task Territory):**

1. Task 7.5d — MobSF `delete_scan` cleanup contract empirical verification
   (analogous to Task 7.5c V4 for ZAP; plan-then-execute pattern).
2. Phase 5.A — design doc Phase 0 drift annotation (D1/D2/D3/D4 + V5 + V17
   + V8) per Task 7.3 5.A pattern (26e9afa).
3. Phase 5.B — ADR-008 addendum (MobSF persistent service → ephemeral
   default; mirror Task 7.5b 5.B ADR-026 addendum 066c81f pattern).
4. Phase 5.C — SPEC §3.2 MobSF subpackage path update (mirrors Task 7.3
   5.C 294427b pattern).
5. Phase 5.D — DEVELOPMENT-PATTERNS entry #6 evaluation (C5
   typed-fields-first 3rd-instance: Nmap + ZAP + MobSF; promotion
   threshold reached).
6. Phase 5.E — SPEC §14.1 asymmetric-cost meta-principle invocation note
   (Q5 lock invocation).
7. VERSIONS.md addendum (D-PLAN-6) — transitive aws-sdk-go-v2 deps not
   individually pinned.
8. iOS section variance verification — empirical at Phase 0 v2 OR Phase 1
   testing (V10 + V13/V16 forward-pins).
9. Async-mode MobSF (`MOBSF_ASYNC_ANALYSIS=1`) — v1 sync; flip when scan
   duration exceeds framework client timeout.
10. ADR-015 enablement task — R2 pre-signed URL pattern bundle.

**Cross-References:** shieldscan-docs commits 02be8cf (design doc) +
4a94c2e (implementation plan); shieldscan-api commit 6403a3f
(D-PLAN-7 Path (c) orchestrator default flip); shieldscan-engine commits
1306ca8 (Task 7.5b DockerServiceRunner framework foundation) + e905afe
(Task 7.3 ZAP consumer; pattern precedent) + 872b2b0 (Task 7.2 Nmap
consumer; pattern precedent) + bfccef8 (Task 7.5c V4 verification; Q5
architectural precedent) + 5503476 (DEVELOPMENT-PATTERNS entry #5;
precedent for C5 promotion at Phase 5.D); SPECIFICATION.md §13 ADR-008
(Phase 5.B addendum target) + ADR-026 + ADR-027 + ADR-015 + ADR-017;
§14.1 (asymmetric-cost meta-principle); §7.1 (mobile_config wire schema)
+ §9.1 (Mobile scans pricing tier).

### §5.D DEVELOPMENT-PATTERNS C5 Typed-Fields-First + Metadata-for-Remainder Promotion Evaluation (Phase 5.D verdict: OUTCOME β — threshold met; promotion declined on "not-duplicative" preamble criterion)

**Authority:** Task 7.4 Phase 5.D pre-verification surface report (this
session; with 8th framing-drift correction caught at execution time
before commit — see Verdict-Correction Lineage below); shieldscan-engine
commit e004300 (Task 7.3 Phase 5.D DEVELOPMENT-PATTERNS evaluation;
canonical C5 scope authority); shieldscan-engine commit 5503476
(Task 7.2 Phase 5.C entry #5 cleanup-uses-detached-context; last
DEVELOPMENT-PATTERNS promotion precedent).

**Scope:** Evaluate whether C5 ("typed-fields-first + Metadata-for-remainder
parser" — per canonical Task 7.3 Phase 5.D scoping in e004300) warrants
promotion to DEVELOPMENT-PATTERNS.md entry #6 at the 3-instance threshold
reached via Nmap + ZAP + MobSF parsers.

**Threshold Status: MET.** Per canonical C5 scope from e004300: *"C5
typed-fields-first + Metadata-for-remainder parser = 2 (nmap/parser.go +
zap/parser.go; only 2 sites populate Metadata field). C5 is closest to
threshold (2/3); next consumer task (Task 7.4 MobSF or Task 7.1 Trivy)
likely creates 3rd Metadata-using parser instance and triggers promotion
evaluation."* MobSF parser (engine commit c15a60d;
`internal/tools/docker/service/mobsf/parser.go` + `sections.go`) populates
Metadata via `buildCodeMetadata` + per-section Metadata maps — 3rd
qualifying instance. Canonical promotion-evaluation trigger condition
from e004300 is now satisfied.

**OUTCOME β Verdict: Promotion declined.** Per DEVELOPMENT-PATTERNS.md
preamble criteria (lines 1-26): patterns are added when they're (a)
genuinely new discipline future engineers might miss AND (b) verified
across 3+ instances AND (c) NOT adequately covered by existing
documentation. C5 satisfies (a) marginally (typed-fields-first ordering
discipline is real but implicit) AND (b) at 3 instances; BUT FAILS (c).
The "typed-fields-first + Metadata-for-remainder" discipline is already
canonically documented at appropriate authority levels:

1. **ADR-027** (shieldscan-docs commit 9a81fe6) defines RawFinding.Metadata
   schema convention: snake_case keys; omit-when-empty;
   remainder-of-structured-payload semantics. ADR-027 IS the authority
   for "Metadata captures the remainder" half of C5.
2. **ToolRunner interface contract docstring** in `internal/tools/runner.go`
   defines the typed-field-population responsibility split: consumer
   populates Title/Severity/Description/CWEID/etc.; framework runner
   enriches ScanID/ToolName/RuleID/DiscoveredAt/RawOutputRef/Fingerprint.
   This contract IS the authority for "typed fields first" half of C5.
3. The ordering itself (typed-fields-first ordering relative to Metadata)
   is the implicit consequence of (1) + (2): if Metadata captures the
   structured-payload remainder per ADR-027, then by definition typed
   fields must be populated first to know what counts as "remainder."
   Re-stating this in DEVELOPMENT-PATTERNS would duplicate ADR-027's
   authoritative scope.

A DEVELOPMENT-PATTERNS entry #6 would primarily restate what ADR-027 +
ToolRunner contract already establish at canonical authority. Per
preamble's "not-duplicative" criterion, promotion is declined.

**Forward-pin for genuinely-novel sub-patterns.** Empirical inspection
during Phase 5.D pre-verification surfaced genuinely-novel discipline
elements present in MobSF parser that are NOT covered by ADR-027 or
ToolRunner contract:

- **Per-section adaptor pattern** for heterogeneous source data (1
  instance — MobSF `sections.go`). Track 2nd instance opportunity at
  Trivy (SBOM section heterogeneity?) or SQLMap (DBMS-fingerprint vs
  injection-finding shape divergence?).
- **Mobile-evidence typed-field cluster** CodeFile/CodeLine/MobileOS/
  Permission/ComponentName (1 instance — MobSF). Track whether
  container-evidence (Trivy) or sca-evidence (Trivy/SQLMap)
  typed-field clusters appear; if 2nd cluster lands, evaluate
  "evidence-field cluster" as composite-pattern candidate.
- **Severity normalization helper** (2 instances — ZAP `mapZAPRisk` +
  MobSF `mapMobSFSeverity`; Nmap hardcoded "Informational"). If Trivy
  ships `mapTrivySeverity` (3rd instance), consider promotion at Trivy
  Phase 5.D.

**Verdict-Correction Lineage (8th framing-drift catch — pre-verification
analysis itself drifted).** Phase 5.D pre-verification surface report
(this session) initially fragmented C5 into ≥4 distinct sub-patterns
(typed-fields-first; Metadata snake_case; identity-field delegation;
target correlation key; severity normalization helper; per-section
adaptor; mobile-evidence typed fields) at mismatched instance counts,
recommending OUTCOME β on "fragmentation" grounds. Direct verification
at P5D.1 surfaced the canonical Task 7.3 5.D C5 scope from engine commit
e004300: C5 is a SINGLE specific sub-pattern ("typed-fields-first +
Metadata-for-remainder parser") — NOT a fragmenting collection.
Pre-verification analysis was framing overshoot relative to canonical
scope. OUTCOME β verdict is preserved BUT the justification is
corrected: threshold IS met at 3 instances per canonical C5 scope;
promotion declined on "not-duplicative" preamble criterion (ADR-027 +
ToolRunner contract already authoritative).

This is the 8th framing-drift correction caught at execution time across
Task 7.4 lifecycle (cumulative count): 7c19eaa fabricated-vs-real engine
commit; VERSIONS.md repo cite; 066c81f repo + addendum-target; ADR-008
forward-pin structure; §14.1 row-addition precedent; OUTCOME γ Phase 5.E
verdict from incomplete repo-scoped search; Phase 5.B precedent-shape
framings; THIS catch (Phase 5.D pre-verification fragmentation overshoot
vs canonical C5 scope). All 8 caught before propagating into committed
text that would matter long-term; verify-then-draft discipline holds.

Historical c15a60d + 3fbb08c forward-pin texts (DRIFT-LOG line 107 +
design doc §3.6) cited "C5 promotion threshold reached" — these become
historical artifacts preserved per historical-authority discipline (no
retroactive edits).

**Cross-References:** shieldscan-engine commit e004300 (Task 7.3 Phase 5.D
DEVELOPMENT-PATTERNS evaluation; canonical C5 scope authority);
shieldscan-engine commit 5503476 (Task 7.2 Phase 5.C entry #5
cleanup-uses-detached-context; last promotion precedent);
shieldscan-engine commit f5d77c8 (Task 7.5a foundation; Nmap parser
instance); shieldscan-engine commit e905afe (Task 7.3 ZAP consumer;
ZAP parser instance); shieldscan-engine commit c15a60d (Task 7.4 MobSF
consumer; MobSF parser + sections.go instance; 3rd qualifying
Metadata-using parser); shieldscan-engine commit a8d82b7 (Task 7.4
Phase 5.E §14.1 invocation tracking note; verdict-correction-lineage
precedent); shieldscan-docs commit 02be8cf (Task 7.4 design doc; Q8
brainstorming-internal C5 nomenclature); shieldscan-docs commit 3fbb08c
(Task 7.4 Phase 5.A drift annotation §3.6); shieldscan-docs commit
9a81fe6 (ADR-027 RawFinding.Metadata schema canonical authority);
DEVELOPMENT-PATTERNS.md preamble (promotion discipline criteria; lines
1-26); SPECIFICATION.md §13 ADR-027 (Metadata snake_case convention
canonical authority); `internal/tools/runner.go` (ToolRunner interface
contract; identity-field delegation authority).

### §14.1 invocation tracking note (Phase 5.E verdict)

Phase 5.E of Task 7.4 evaluated whether Q5 architectural decision
(cfg.EphemeralContainer = true v1 default for MobSF consumer) warrants a
new entry in SPECIFICATION.md §14.1 invocation enumeration table.

**Verdict: OUTCOME β** — Task 7.4 Q5 is NOT a §14.1 invocation; DRIFT-LOG
note added (mirrors Task 7.5b 5.E precedent c8840a1 OUTCOME γ + Task 7.3
5.E precedent 7c19eaa OUTCOME β).

**Reasoning.** §14.1 is ADR-scoped per its own text (SPECIFICATION.md
lines 2266 + 2275 + 2284): *"invoked in 6 ADRs across the project
corpus"*; *"ADR drafters should invoke §14.1 when..."*; *"§14.1 only when
cost-asymmetry is genuinely load-bearing for the decision; otherwise,
standard threshold-counting reasoning suffices."* Task 7.4 is a CONSUMER
task (not an ADR); decisions live in design doc 02be8cf + implementation
plan 4a94c2e + Phase 5.A drift annotation 3fbb08c + DRIFT-LOG (this
file), NOT §13 ADR registry. Per Task 7.5b 5.E precedent (c8840a1) +
Task 7.3 5.E precedent (7c19eaa), non-ADR resolution-lock decisions do
not constitute §14.1 invocations regardless of whether asymmetric-cost
framing was rhetorically applied.

**Q5 architectural reasoning (rhetorical-frame use, not formal
invocation).** Q5 invoked asymmetric-cost framing: (a) bounded ephemeral
container startup cost — measured in seconds; pricing tier §9.1 caps
mobile scans (Growth=2/mo; Business rate-limited); startup amortization
win is smaller than ZAP's high-frequency web-scan pattern; (b) unbounded
cleanup-contract-uncertainty cost — Task 7.5c V4 verification
empirically demonstrated configuration-scoped state leak (S7
PARTIAL_RESET orphan user records; S8 NOT_RESET custom scan policies;
S9 NOT_RESET per-policy attack-strength tuning) under analogous ZAP
newSession; MobSF V5 forward-pin from Task 7.5b ("Suppression/user/
settings table persistence UNCLEAR") flags matching territory; same
failure mode would ship multi-tenant data leakage. Asymmetric-cost
calculus tilts hard toward ephemeral default until Task 7.5d empirically
verifies MobSF delete_scan cleanup contract completeness. Per §14.1's
own Tension acknowledgment, rhetorical-frame use ≠ formal invocation.

**Verdict-correction lineage.** This subsection revises an earlier
OUTCOME γ chat-verdict (skip-with-rationale) issued during Phase 5.E
pre-implementation evaluation. PR.4 pre-remediation verification surface
report (this session) surfaced that the OUTCOME γ chat-verdict was based
on incomplete repo-scoped search — specifically, the chat claimed
Task 7.3 Phase 5.E commit 7c19eaa was fabricated, when in fact the
commit is a real shieldscan-engine DRIFT-LOG entry from 2026-05-10.
Correcting search scope confirms OUTCOME β precedent across Task 7.5b
(c8840a1; OUTCOME γ) + Task 7.3 (7c19eaa; OUTCOME β); Task 7.4 5.E
mirrors per symmetric coverage discipline. Engine-side DRIFT-LOG note
granularity preserves SPEC §14.1 Tension acknowledgment while
maintaining audit-trail coverage.

**Forward-pin for Phase 5.B.** ADR-008 addendum (Phase 5.B; deferred) is
the architecturally-appropriate landing site for SPEC §14.1 invocation
table row 7 enumeration IF a fresh ADR-scoped invocation lands. Per
current OUTCOME β verdict, Task 7.4 Q5 is NOT an ADR-scoped invocation
(consumer-task derivative; per existing precedent); §14.1 table
extension at Phase 5.B is contingent on whether the ADR-008 addendum
itself constitutes a fresh ADR-scoped invocation of the meta-principle.
If future scope expansion makes §14.1 track non-ADR invocations
(consumer-task design-doc decisions; Phase 0 resolution locks),
Task 7.4 Q5 is an eligible candidate alongside Task 7.5b V4/V5 +
Task 7.3 Q5/Q6/Q7/Q8.

**Cross-references.** shieldscan-engine commit c8840a1 (Task 7.5b 5.E
precedent; OUTCOME γ); shieldscan-engine commit 7c19eaa (Task 7.3 5.E
precedent; OUTCOME β); shieldscan-engine commit c15a60d (Task 7.4
engine close; Q5 ephemeral lock + processor wiring); shieldscan-engine
commit bfccef8 (Task 7.5c V4 verification empirical findings; direct
architectural precedent); shieldscan-engine commit 1306ca8 (Task 7.5b
DockerServiceRunner framework foundation); shieldscan-docs commit
02be8cf (Task 7.4 design doc); shieldscan-docs commit 3fbb08c (Task 7.4
Phase 5.A drift annotation §3.6); shieldscan-docs commits 124f5aa +
c6a79e0 (Task 7.5c Phase D); shieldscan-docs SPECIFICATION.md §14.1
(asymmetric-cost meta-principle promotion 496cf6c); SPECIFICATION.md
§13 ADR-008 (Phase 5.B addendum target).

---

## 2026-05-09 — Task 7.5c V4 ZAP Cleanup Verification (Empirical Execution)

**Authority:** `plans/2026-05-09-task-7.5c-zap-cleanup-verification-plan.md`
(commit 5a253d2 original; commit 124f5aa Phase D.1 verification record) in
shieldscan-docs.

**Scope.** Empirical verification of ZAP `newSession` cleanup contract against
pinned ZAP digest `sha256:8770b...` (ZAP 2.17.0). Executed against OWASP
juice-shop testbed (`bkimminich/juice-shop:latest`). 9 surfaces tested + 3
idempotency/failure-mode tests. NO engine code changes; verification confirms
existing Task 7.5b V4 Option γ ephemeral lock is empirically correct.

### Per-Surface Verdicts

| Surface | Verdict | Note |
|---|---|---|
| S1 Spider History | ✅ RESET_COMPLETE | 1→0 scans; scan ID returns `does_not_exist` |
| S2 Active Scan History | ✅ RESET_COMPLETE | 1→0 scan records |
| S3 Alert List | ✅ RESET_COMPLETE | 32→0 alerts |
| S4 Target Context | ✅ RESET_COMPLETE | `verify-test` context cleared |
| S5 Scope Config | ✅ RESET_COMPLETE | cascade with S4 |
| S6 Auth Method | ✅ RESET_COMPLETE | cascade with S4 |
| S7 User Contexts | ⚠️ PARTIAL_RESET | Orphan user records persist (id=40 ctx=2 even though ctx 2 reset) |
| S8 Attack Policies | ⚠️ NOT_RESET | Custom `verify-policy` survives `newSession` |
| S9 Plugin Attack Strength | ⚠️ NOT_RESET | id=4 Injection `attackStrength=HIGH` persists |

### Idempotency + Failure Mode Tests

- **IF1** (idempotent `newSession` on clean state): ✅ Both calls return
  `{"Result":"OK"}`
- **IF2** (`newSession` during in-progress ascan): ✅ Returns OK; in-progress
  scan cleanly terminated
- **IF3** (insufficient privileges): N/A (single-key API)

### Cumulative Verdict

**RECOMMEND RETAIN `cfg.EphemeralContainer = true` for ZAP.** Per Task 7.5c
plan §7 evaluation framework: *"Any surface NOT_RESET OR PARTIAL_RESET →
RECOMMEND retain `cfg.EphemeralContainer = true` (cleanup contract
incomplete)."* Three surfaces fail clean reset; ephemeral lock empirically
validated as architecturally correct (NOT transitional).

### Architectural Insight (Documentation Gap)

ZAP's `newSession` is session-state-only; user definitions (`/JSON/users/...`)
+ custom scan policy registry (`/JSON/ascan/.../addScanPolicy`) + per-policy
attack-strength + alert-threshold tuning (`setPolicy*` / `setScanner*`
actions) are stored at ZAP-instance level (configuration-scoped), NOT
session-scoped. This distinction is not surfaced in public REST API docs at
zaproxy.org/docs/api/.

### Security Implication

Warm-pool path with `newSession`-as-cleanup-mechanism would have shipped
multi-tenant data leakage vulnerability: prior-tenant user records + custom
policies + plugin tuning would persist into next-tenant scans. Q6 ephemeral
lock per Task 7.5b V4 Option γ averts this.

### Phase D Artifacts Landed

- Phase D.1 (shieldscan-docs commit 124f5aa): Task 7.5c plan §11 Verification
  Execution Record
- Phase D.2 (shieldscan-docs commit c6a79e0): Task 7.5b design doc + Task 7.3
  design doc V4-verified annotations
- Phase D.3 (this commit): shieldscan-engine DRIFT-LOG empirical findings
  entry

### Forward-Pins (Future-ADR-Territory)

1. **M9 multi-tenant ZAP scope:** if multi-tenant scenarios with shared ZAP
   instances surface in M9, only safe paths are (a) per-tenant ephemeral
   container (current Task 7.5b V4 default) OR (b) full container restart
   between tenants (vs `newSession`). Warm-pool with `newSession` cleanup is
   empirically ruled out by S7/S8/S9 findings.
2. **Upstream documentation MR opportunity:** zaproxy.org/docs/api/ has
   documentation gap on `newSession` scope (session-state-only; not
   user/policy/plugin-state). Community contribution opportunity; not
   blocking.
3. **Future ZAP version re-verification:** if ZAP version upgrades beyond
   2.17.0 (current pinned digest `sha256:8770b...`), re-execute V4
   verification at new digest before assuming behavior unchanged. ZAP cleanup
   contract behavior may change across versions.
4. **Configuration-scoped reset API surveillance:** if future ZAP API
   endpoint surfaces that resets configuration-scoped state (users + custom
   policies + plugin tuning) via single call, warm-pool path becomes viable.
   Currently no such endpoint documented; surveillance forward-pin.

### Cross-References

- shieldscan-docs commit 5a253d2 (Task 7.5c plan original)
- shieldscan-docs commit 124f5aa (Task 7.5c Phase D.1 verification record)
- shieldscan-docs commit c6a79e0 (Task 7.5c Phase D.2 design doc annotations)
- shieldscan-docs commit 3067c92 (Task 7.5b design doc; V4 Option γ
  resolution lock annotated D.2)
- shieldscan-docs commit 26e9afa (Task 7.3 Phase 5.A design doc; Q6
  ephemeral path annotated D.2)
- shieldscan-engine commit 1306ca8 (Task 7.5b framework; V4 Option γ
  ephemeral lock)
- shieldscan-engine commit e905afe (Task 7.3 engine close;
  `cfg.EphemeralContainer = true` for ZAP)
- SPECIFICATION.md §13 ADR-026 (DockerRunner family); §14.1
  (asymmetric-cost meta-principle)

---

## 2026-05-09 — Task 7.3 ZAP Consumer (DAST)

**Authority:** `plans/2026-05-09-task-7.3-zap-consumer-design.md` (commit
682cfcc in shieldscan-docs); `plans/2026-05-09-task-7.3-zap-consumer-implementation.md`
(commit e98a8e4 in shieldscan-docs); brainstorming chain Q1–Q9 (in conversation
memory); Phase 0 + Phase 1 + Phase 2 surface reports.

**Scope.** ZAP consumer subpackage at `internal/tools/docker/service/zap/`
(7 prod + 7 test files; ~1781 LoC); cross-package modifications to
`deploy/docker-compose.services.yml` + `deploy/docker_compose_test.go` (Q3
lock; ZAP service entry removed) + `internal/tools/runner.go` (Q6 D1 JSON tags
on existing AuthConfig type). First DockerServiceRunner consumer (per Task
7.5b framework commit 1306ca8).

### Phase 0 Empirical Verification (V0–V18)

Phase 0 caught 5 critical design adjustments + 1 NEW infrastructure finding:

- **V0** Host header routing: ZAP daemon distinguishes API vs proxy by Host
  header; consumer-local `zapQueryParamAuth` AuthFunc closure sets
  `req.Host = "zap"` for all API requests.
- **V5/V17** policy names DRIFT: ZAP 2.17.0 ships 22 policies (not 9
  documented); `ascan.go` `zapPolicyAllowlist` hardcodes the 22 actual names.
- **V6** `cweid` DRIFT: JSON STRING not int; `parser.go` pass-through directly
  to `RawFinding.CWEID` without `strconv.Itoa`.
- **V8** Severity normalization STOP_GATE_RESOLVED: shieldscan-api enum is
  lowercase; `parser.go` `mapZAPRisk` normalizes `"High"→"high"` etc;
  `"False Positive" → drop=true` (V9 intersection).
- **V12** tags shape DRIFT: ZAP `tags` is `map[string]string` with structured
  keys (`OWASP_*`, `CWE-*`, `POLICY_*`, `SYSTEMIC`); `parser.go` `extractZAPTags`
  filters `OWASP_*`+`CWE-*` keys, drops `POLICY_*`+`SYSTEMIC` noise; raw tags
  preserved in `Metadata["tags_raw_json"]`.
- **V13** form-based auth STOP_GATE_PASS: `authMethodConfigParams` URL-encoded
  format ~150–300 chars; well within ExtraArgs escape-hatch capacity; Q6 lock
  holds.
- **V3** header backward-compat WORKS but doesn't change Q7(B) lock.
- **V1+V2+V4+V10+V11+V16+V18** RESOLVED with clean Phase 1 paths.
- **V14** PARTIAL (`userId` silent-pass; Phase 1 forward-pin).
- **V15** FORWARD-PINNED (session re-auth empirical out-of-scope).

### Phase 1 Deviations (D1–D7)

- **D1** — `AuthConfig` pre-exists on `tools.Target` struct (line 138; not
  `ScanConfig` per design doc Q6); engine had partial Task 3.X-vintage work;
  Phase 1 added JSON tags only.
- **D1.b** — JSON tags on `tools.AuthConfig` are redundant (internal-only
  struct; wire deserialization happens via `events.JobAuth` per Phase 2 V2.3
  finding). Tags are harmless; no action needed.
- **D2** — `runner_test.go` did not exist; created from scratch.
- **D3** — `service.DockerClient` does not exist; `docker.DockerClient` is the
  type alias (per Task 7.5b 1306ca8 D1 deviation precedent); switched import.
- **D4** — `extraArgsAuthMap` unused warning resolved via forward-pin warn-log
  call in `zap.NewBuildScan`.
- **D5** — staticcheck QF1011 short var decl preference; resolved with
  shorthand.
- **D6** — staticcheck SA4017 no-op if-block in stub; replaced with
  comment-only.
- **D7** — gofmt thread-count column drift in `spider_test.go`; auto-corrected.

### Phase 2 Verification + Disposition (V2.1–V2.6)

Phase 2 surfaced shieldscan-api comprehensive credentials infrastructure
already shipped (M3 Task 3.X vintage): Pydantic `CredentialRequest`
discriminated union (5 types matching engine); SQLAlchemy `ProjectCredential`
with Fernet encryption; migration `d4f6b1e9a527`; route tests. Engine
wire-deserialization via `events.JobAuth` aligns with SPEC §7.1;
`processor.jobDispatchToTarget` bridges wire→engine `target.AuthConfig` (lines
421–440). ADR-015 forcing function intentionally blocks runtime activation:
orchestrator emits `auth=None` per `test_dispatch_payload_auth_is_null_pending_adr_015`
pin.

**Phase 2 disposition: OUTCOME (b)** — forward-pin ADR-015 enablement to
separate task; engine Phase 4 ships standalone. ZERO shieldscan-api files
modified in this commit.

### Forward-Pins

1. **Task 7.3.x or M5+ ADR-015 enablement task:** orchestrator decrypts
   `ProjectCredential`; serializes to wire `{type, data}` shape; lifts
   `test_dispatch_payload_auth_is_null_pending_adr_015` pin.
2. **v2 wire-schema Fields expansion:** `events.JobAuth` adds
   `Fields map[string]string` when 2nd auth-supporting consumer lands OR
   form-auth path activated.
3. **CredentialRequest discriminator drift** (audit-only): API uses
   `auth_type`; engine wire uses `type`; orchestrator dispatch must rename
   when ADR-015 lands.
4. **Task 7.3 Phase 5.A design doc revision:** Q6 placement (Target not
   ScanConfig); V5/V17 22 actual policy names; V6 cweid string pass-through;
   V12 tags map shape extraction; V0 Host header design adjustment.
5. **Task 7.5b documentation cleanup:** design doc 3067c92 + ADR-026 addendum
   066c81f reference ZAP using `WithAPIKeyHeader` (incorrect per Q7
   verification).
6. **Task 7.5c V4 verification execution:** ZAP `newSession` cleanup contract
   empirical work.
7. **v2 typed-enum AuthConfig.Type expansion:** form_based path empirical
   config formats verified (V13 PASS); ready for v2 enablement when ADR-015
   lifted.
8. **Mode D AJAX spider v2:** when SPA customer demand surfaces.
9. **Pagination upgrade** (Q8 Option ii): if execution surfaces alert count
   >5000.
10. **WithAPIKeyQueryParam framework helper promotion:** when 2nd
    query-param-auth tool surfaces (Phase 5.D Task 7.5b 3-instance threshold
    gate).

### Quality Gate (Phase 3 final)

- gofmt clean; go vet clean; golangci-lint zero issues
- `go test -race -count=1` 23/23 packages green
- `service/zap` coverage 87.3% (above 80% target)
- 39 new tests landed (35 zap subpackage + 4 runner.go AuthConfig)

### Cross-References

- shieldscan-engine commit 1306ca8 (Task 7.5b DockerServiceRunner framework)
- shieldscan-engine commit 872b2b0 (Task 7.2 Nmap consumer pattern precedent)
- shieldscan-engine commit f5d77c8 (Task 7.5a foundation)
- shieldscan-engine commit 5503476 (DEVELOPMENT-PATTERNS entry #5;
  cleanup-uses-detached-context applies to v2 warm-pool)
- shieldscan-engine commit 3a17274 (Task 7.5b Phase 5.D no-promotions)
- shieldscan-docs commit 682cfcc (Task 7.3 design doc)
- shieldscan-docs commit e98a8e4 (Task 7.3 implementation plan)
- shieldscan-docs commit 5a253d2 (Task 7.5c V4 verification plan)
- shieldscan-docs commit 066c81f (Task 7.5b ADR-026 addendum)
- shieldscan-docs commit 3067c92 (Task 7.5b design doc)
- SPECIFICATION.md §7.1 (auth block wire schema); §9.1 (pricing tiers; Quick +
  Full); §13 ADR-008 (MobSF DockerServiceRunner consumer precedent); §13
  ADR-015 (decrypted credentials in Redis transit; forcing function); §13
  ADR-026 (canonical DockerRunner architecture + ContainerFactory addendum);
  §13 ADR-027 (RawFinding.Metadata schema); §14.1 (asymmetric-cost
  meta-principle).

### DEVELOPMENT-PATTERNS evaluation note (Phase 5.D verdict)

Phase 5.D of Task 7.3 evaluated 5 candidate patterns surfaced from Phase 1
implementation against the 3-instance promotion threshold (per
DEVELOPMENT-PATTERNS entry #5 precedent commit 5503476).

**Verdict: NO PROMOTIONS** — threshold gate held. DRIFT-LOG note added
(mirrors Task 7.5b 5.D 3a17274 no-promotions precedent).

**Per-candidate instance counts (grep-grounded):**

1. **`req.Host` AuthFunc override** (consumer-local Host header set for
   tool-specific API routing) — 1 instance (`zap/auth.go`
   `zapQueryParamAuth`). Forward-pin: re-evaluate when 2nd tool surfaces
   Host-header routing requirement.
2. **Severity normalize + drop tuple** (`mapXRisk(risk) (severity, drop bool)`
   parser-side normalization with drop-decision flag) — 1 instance
   (`zap/parser.go` `mapZAPRisk`). Forward-pin: MobSF/SQLMap/Trivy
   parsers may invoke similar shape if upstream-severity-enum diverges
   from shieldscan-api Pydantic Literal.
3. **Structured-tags-map filter** (`extractTags(map[string]string) []string`
   filtering by structured key prefix; preserves raw via Metadata) —
   1 instance (`zap/parser.go` `extractZAPTags`). semgrep's
   `extractCategoryAsTags` is different shape (singleton-from-string,
   not map-keys-filter). Forward-pin: re-evaluate when 2nd consumer
   surfaces structured-tags-map upstream shape.
4. **Tool-version-specific hardcoded allowlist** (consumer-side allowlist
   matching tool-version-specific values; e.g., `zapPolicyAllowlist` 22
   ZAP 2.17.0 names) — 1 instance (`zap/ascan.go`). Forward-pin:
   ZAP version upgrade requires allowlist refresh; likely 2nd instance
   when MobSF/Trivy surfaces similar tool-version-specific value-set.
5. **Typed-fields-first + Metadata-for-remainder parser** (Title/
   Severity/Description/CWEID/TargetURL typed; structured payload via
   Metadata snake_case keys; omit-when-empty discipline) — **2 instances**
   (`nmap/parser.go` + `zap/parser.go`; only 2 sites populate `Metadata:`
   field — all M5/M6 native tools predate ADR-027 Metadata schema).
   Closest to threshold; next consumer task (likely Task 7.4 MobSF or
   Task 7.1 Trivy) creates 3rd instance + triggers promotion evaluation.

**Threshold-gate honored.** Per Task 7.5b 5.D precedent (3a17274) +
entry #5 precedent (5503476): 3-instance threshold is the gate;
speculative promotion at 1-2 instances would inflate
DEVELOPMENT-PATTERNS surface area. Re-evaluation triggers: Task 7.4
(MobSF) lands 3rd Metadata-using parser → promote C5; Task 7.1 (Trivy)
adds another Metadata-using parser → C5 reaches 4-instance super-
majority confirming pattern. C1-C4 likely stay tool-specific
indefinitely.

**Cross-references:** shieldscan-engine commit 3a17274 (Task 7.5b 5.D
no-promotions precedent); shieldscan-engine commit 5503476
(DEVELOPMENT-PATTERNS entry #5; cleanup-uses-detached-context promotion
at 3-instance threshold; canonical promotion-format precedent);
shieldscan-engine commit e905afe (Task 7.3 engine close); shieldscan-engine
commit 872b2b0 (Task 7.2 Nmap parser; precedent C5 1st instance);
shieldscan-engine DEVELOPMENT-PATTERNS.md.

### ADR evaluation note (Phase 5.B verdict)

Phase 5.B of Task 7.3 evaluated whether Task 7.3's architectural
commitments warrant ADR territory (addendum to existing ADR OR new ADR).

**Verdict: OUTCOME iii** — no ADR action; Task 7.3 is consumer-task scope.
DRIFT-LOG note added (mirrors Task 7.5b 5.D 3a17274 + 5.E 7c19eaa no-action
patterns).

**ADR registry references found:**
- ADR-026 line 2104 (ContainerFactory addendum): "future ZAP (Task 7.3)"
  — names Task 7.3 as forthcoming consumer of existing framework
- ADR-027 line 2175: illustrative ZAP Metadata keys (explicitly marked
  illustrative; canonical contracts land in consumer task design doc)
- ADR-027 line 2211 Triggers to revisit #1: Metadata key contract conflict
  check — Task 7.3 is 2nd consumer; no conflict (only `target` shared
  with Nmap; aligned semantics)
- ADR-027 line 2225 Open follow-up: "Future Trivy/SQLMap/ZAP/MobSF
  consumer tasks: each lands per-tool Metadata key contract" — Task 7.3
  fulfills this forward-pin

**Evaluation against Task 7.5b 5.B precedent (066c81f) ADR-territory criteria:**

- **(a) wire-schema:** D1.b confirmed `events.JobAuth` + `Target.AuthConfig`
  pre-existed (Task 3.X M3 vintage); JSON tags addition was redundant. NO
  new wire-schema primitive.
- **(b) cross-repo:** Phase 2 OUTCOME b ZERO shieldscan-api files
  modified; ADR-015 enablement forward-pinned to separate task. NO new
  cross-repo commitment.
- **(c) downstream-pipeline:** Q8 RawFinding mapping uses existing
  ADR-027 Metadata schema; snake_case keys per Nmap precedent. NO new
  downstream-pipeline commitment.

Task 7.5b 5.B (066c81f) added a ContainerFactory Extension addendum to
ADR-026 because Task 7.5b extended the ADR-026 framework with a NEW
primitive (V2 ContainerFactoryFunc + Config.ContainerFactory field +
DefaultContainerFactory). Task 7.3 by contrast is a CONSUMER task
fulfilling forward-pins set by prior ADRs (ADR-026 + ADR-027); did not
extend ANY ADR territory.

**ADR-027 illustrative-key drift note** (documentation hygiene; NOT
ADR-territory): ADR-027 line 2175's illustrative ZAP keys (`http_method,
request_headers_hash, response_code, attack_vector`) differ from Task 7.3's
actual canonical contract enumerated in Phase 1 implementation
(`confidence, plugin_id, wasc_id, http_method, attack_vector, evidence,
target, alert_ref, input_vector, other_info, solution, zap_message_id,
zap_source_id, tags_raw_json`). ADR-027 explicitly framed these as
"illustrative; canonical key contracts land in each consumer task's design
doc + package docstring" — so drift is by-design. ADR-027 update could
optionally cross-reference Task 7.3 design doc 26e9afa for canonical
contract; not required.

**Cross-references:** shieldscan-docs commit 066c81f (Task 7.5b 5.B
precedent; OUTCOME (i) addendum to ADR-026 — different shape because Task
7.5b extended framework primitive); shieldscan-engine commit 3a17274
(Task 7.5b 5.D no-promotions precedent); shieldscan-engine commit
7c19eaa (Task 7.3 5.E DRIFT-LOG note pattern); shieldscan-engine commit
e905afe (Task 7.3 engine close); shieldscan-docs SPECIFICATION.md §13
ADR-026/ADR-027/ADR-015/ADR-008.

### §14.1 invocation tracking note (Phase 5.E verdict)

Phase 5.E of Task 7.3 evaluated whether Q5/Q6/Q7/Q8 brainstorming locks +
Phase 0/1/2 cost-asymmetry-driven decisions warrant new entries in
SPECIFICATION.md §14.1 invocation enumeration table.

**Verdict: OUTCOME β** — Task 7.3 decisions are NOT §14.1 invocations;
DRIFT-LOG note added (mirrors Task 7.5b 5.E precedent c8840a1 OUTCOME γ).

**Reasoning.** §14.1 is ADR-scoped per its own text (lines 2266 + 2275 +
2284 in shieldscan-docs SPECIFICATION.md): *"invoked in 6 ADRs across the
project corpus"*; *"ADR drafters should invoke §14.1 when..."*; *"§14.1
only when cost-asymmetry is genuinely load-bearing for the decision;
otherwise, standard threshold-counting reasoning suffices."* Task 7.3 is a
CONSUMER task (not an ADR); decisions live in design doc 682cfcc +
implementation plan e98a8e4 + DRIFT-LOG (this file), NOT §13 ADR registry.
Per Task 7.5b 5.E precedent (c8840a1), non-ADR resolution-lock decisions
do not constitute §14.1 invocations regardless of whether asymmetric-cost
framing was rhetorically applied.

**Per-decision evaluation:**

- Q5 escape hatch over speculative custom policy → standard YAGNI;
  not threshold-overriding
- Q6 reframe iterations across Phase 0 V8 + Phase 1 D1 + Phase 2 V2.3 →
  verification gating; not architectural threshold override
- Q6 cookie-only-v1 over γ-full → verification-gating (V13 form-based
  formats not empirically verified at design time); not §14.1 territory
- Q7(B) doc-canonical over Q7(A) undocumented backward-compat → risk-
  asymmetric ("ship documented behavior") but not threshold-overriding;
  standard forward-stability reasoning
- Q8(iv) bulk-fetch over Q8(ii) defensive-pagination → standard
  trigger-fires-then-promote forward-pin; not threshold-overriding

**Rhetorical use vs formal invocation.** Task 7.3 design doc 682cfcc §1
Executive Summary + §7 Process Acknowledgment did rhetorically reference
"asymmetric-cost" framing in Q6 lock + Path Y verification — but per
§14.1's own "tension acknowledgment", rhetorical-frame use ≠ formal
invocation. If future scope expansion makes §14.1 track non-ADR
invocations (consumer-task design-doc decisions; Phase 0 resolution
locks), Task 7.3 Q5/Q6/Q7/Q8 + Phase 0 V8 are eligible candidates
alongside Task 7.5b V4/V5.

**Cross-references:** shieldscan-engine commit c8840a1 (Task 7.5b 5.E
precedent; OUTCOME γ); shieldscan-engine commit e905afe (Task 7.3 engine
close); shieldscan-docs commit 26e9afa (Task 7.3 Phase 5.A); shieldscan-docs
SPECIFICATION.md §14.1 (asymmetric-cost meta-principle promotion 496cf6c).

---

## 2026-05-09 — Task 7.5b (DockerServiceRunner framework)

**Status:** Engine-side closed. Doc-side close-out (Phase 5) forthcoming.

**Commits.** Pre-implementation artifacts: shieldscan-docs commits 8bafa6b
(design doc) + 2c8781f (implementation plan) + 3067c92 (design doc revision;
Phase 0 resolution locks) + 1362c5c (implementation plan revision). Engine
implementation: this commit (Phase 1+3 atomic).

### Phase 0 acknowledgments

**Brainstorming-chain misframing.** Q1–Q9 brainstorming chain (in conversation;
pre-design-doc) made 9 decisions against an incorrect "design DockerServiceRunner
from scratch" baseline. Phase 0 verification step (V8) surfaced pre-existing
`internal/tools/docker_service.go` (366 LoC; M5.3 + ADR-006). Phase 0.5 verified
zero active consumers; V8 Option (c) Replace locked. The discipline pattern's
verification step caught the misframing at design-doc-Phase-0 boundary, not at
implementation time. Pre-implementation artifacts (8bafa6b + 2c8781f) were
revised (3067c92 + 1362c5c) to align with verified repo state.

**4 architectural Phase 0 resolution locks.**

- **V8 Option (c) Replace** — `internal/tools/docker_service.go` (366 LoC) deleted;
  new framework lands at `internal/tools/docker/service/` subpackage;
  framework-symmetric with Task 7.5a's `internal/tools/docker/`.
- **V2 Option (α)** — Task 7.5a framework extended with `ContainerFactoryFunc` +
  `Config.ContainerFactory` hook + `DefaultContainerFactory` exported function
  (~30–50 LoC additive to f5d77c8); preserves Task 7.2 Nmap consumer
  backward-compat (`DefaultContainerFactory` replicates existing `newContainer`
  behavior).
- **V4 Option (γ)** — `cfg.EphemeralContainer = true` as ZAP default v1;
  rationale: ZAP `newSession` reset surfaces (9) NOT VERIFIED in public docs;
  security-consequential uncertainty side-stepped via fresh-container-per-scan;
  verification path forward-pinned to dedicated future task.
- **V5 Option (γ)** — MobSF md5-tracked cleanup with WarmPool failure-replace
  fallback; per Phase 0 source-code reading verified per-scan-by-hash model;
  consumer tracks `lastScanMD5` in `CleanupFunc` closure; WarmPool
  failure-replace handles in-progress-scan + network-failure edge cases.

### Phase 1 deviations (auto-corrected at implementation time)

- **D1.** `dockerClient` interface unexported — service subpackage cannot
  reference type from another package. Resolution: added
  `type DockerClient = dockerClient` single-line alias in `container.go`;
  preserves all internal references; enables cross-package factory function
  literals.
- **D2.** `dockerClient` missing `ContainerInspect` method — required for
  `ServiceContainerFactory` dynamic-port discovery. Resolution: extended
  `dockerClient` interface with `ContainerInspect`; added passthrough on
  `productionClient`; added stubs in 3 test helper files
  (`docker/testhelpers_test.go`, `docker/nmap/testhelpers_test.go`,
  `docker/container_test.go` `fakeClient`).
- **D3.** `Container` struct unexported `cli`/`log` fields — service factory in
  another package cannot construct via struct literal. Resolution: added
  exported `NewServiceContainer(id, image, baseURL, cli, log) *Container`
  constructor + `BaseURL` exported field on `Container` struct; preserves all
  existing `Container` internal usage.
- **D4.** `PollOpts.MaxDuration` default referenced non-existent
  `ServiceConfig.ScanTimeout` (verbatim issue from design doc). Resolution: flat
  30-minute default at framework level via `normalizePollOpts`; documented in
  `client.go` docstring; rationale captured here.
- **D5.** `container.NetworkSettingsBase` deprecation in Docker SDK v28.5 (will
  move in v29). Resolution: populate via direct field assignment on
  `container.NetworkSettings.Ports` + `nolint:staticcheck` pragma + comment for
  future v29 migration; existing Docker SDK pinning preserved.
- **D6.** `http.NewRequest` lint complaint — golangci-lint prefers
  `http.NewRequestWithContext`. Resolution: converted to
  `http.NewRequestWithContext(context.Background(), ...)` in 3 test sites.

### Phase 2 compression

**Phase 2 subsumed by Phase 1.** Implementation plan 1362c5c Phase 2 scope was
"DockerServiceRunner.Run lifecycle wiring" — separated from Phase 1 "framework
primitives." Reality: Phase 1's expanded scope (V2 framework extension + V8
atomic replace) required `service.go`'s `Run` method to land coherently with its
primitives (`ContainerFactoryFunc` + `NewServiceContainer` + `ContainerInspect`
+ `BaseURL`). Stub→flesh-out split would have produced unbuildable intermediate
state. Phase 1 landed `Run` at full production shape with both
`EphemeralContainer` + warm-pool branches + integration tests. Phase 2 had no
remaining scope.

### Phase 3 deviation

- **D7.** `doc.go` skipped because `errors.go` already carries comprehensive
  package-level docstring covering V8/V2/V4/V5 resolution locks + ADR-026
  cross-reference. Plan-prescribed `doc.go` was strict subset. Verification
  surfaced redundancy; created transiently; observed godoc concatenation
  duplication; removed. Net Phase 3 substantive change: `DockerServiceRunner`
  consumer-integration docstring expanded with ZAP example.

### Discipline pattern observation

6 Phase 1 implementation-time deviations + 1 Phase 3 verification-time deviation
= 7 deviations caught by verification step; 0 deviations shipped without
acknowledgment. The discipline pattern (verification at every load-bearing
boundary) caught what pre-implementation guidance missed. Specifically: Phase 0
caught brainstorming-chain misframing; Phase 1 implementation caught 6
cross-package + framework-integration edge cases; Phase 3 caught documentation
redundancy. Each surface report enabled auto-correction + audit-trail honesty
rather than silent shipping.

### Forward-pins

- **Phase 5 docs followup** (forthcoming): design doc post-implementation
  alignment commit; ADR-026 addendum evaluation for `ContainerFactory` hook (V2
  framework extension); SPEC §3.2 architecture diagram update
  (`docker_service.go` path → `docker/service/` subpackage); cross-references to
  this commit.
- **V4 ZAP cleanup verification** — dedicated future task (Task 7.5c or similar)
  does empirical `newSession` verification (spin up local ZAP; populate state
  across 9 surfaces; observe `newSession` behavior; OR Java source-code
  reading); if `newSession` found COMPLETE, flip ZAP default from
  `EphemeralContainer = true` to warm pool with reset cleanup; restores
  warm-pool startup amortization for ZAP.
- **Task 7.3 (ZAP) consumer** — first DockerServiceRunner consumer; consumer-side
  `BuildScan` logic + parser; `AuthFunc` construction
  (`service.WithAPIKeyHeader`); `EphemeralContainer = true` config.
- **Task 7.4 (MobSF) consumer** — second consumer; md5-tracked `CleanupFunc`
  closure; warm-pool path.
- **Future shared `internal/tools/docker/dockertest/` subpackage** — if
  3rd-instance promotion threshold met (Nmap consumer + DockerServiceRunner
  consumer = 2 instances; Trivy/SQLMap may push to 3).

### DEVELOPMENT-PATTERNS evaluation note (Phase 5.D verdict)

Three candidate patterns surfaced from Task 7.5b implementation:

1. **Framework-extension hook with backward-compat default** (`Config.X` field +
   `DefaultX` exported function + caller routes through field-or-default).
2. **EphemeralContainer-vs-warm-pool consumer opt-out flag** (`cfg.X bool` →
   `Run` branches into two distinct lifecycle paths).
3. **Typed auth helpers + AuthFunc-style escape hatch** (`With*` constructors
   returning function-type + arbitrary-closure escape hatch).

Phase 5.D grep-grounded instance counts in shieldscan-engine corpus: candidate
1 = 1 instance (`DefaultContainerFactory`/`ContainerFactoryFunc` in
`internal/tools/docker/warmpool.go`; commit 1306ca8); candidate 2 = 1 instance
(`EphemeralContainer` in `internal/tools/docker/service/service.go`; commit
1306ca8); candidate 3 = 0 corpus-wide instances of the pattern (Task 7.5b's
2 `With*` helpers are 2 helpers within 1 framework, not 2 corpus-pattern
occurrences). None reached the 3-instance threshold for DEVELOPMENT-PATTERNS
promotion. Forward-pin: re-evaluate when Task 7.3 (ZAP) + Task 7.4 (MobSF) +
future M7 consumer tasks land additional instances. If candidate 1 picks up a
2nd instance via M7 consumer-specific factory variants, evaluate at that
point; same for candidate 2 if a future tool surfaces a similar
warm-pool-vs-ephemeral opt-out shape.

### §14.1 invocation tracking note (Phase 5.E verdict)

Task 7.5b V4/V5 resolutions invoked asymmetric-cost reasoning during Phase 0
resolution-lock decisions (V4 ZAP `EphemeralContainer = true` default; V5 MobSF
md5-tracked cleanup); not added to SPEC §14.1 invocation table because §14.1 is
currently scoped to ADR invocations only (per shieldscan-docs commit 496cf6c;
§14.1 lines 2216/2232/2247 enumerate "ADRs" specifically). Task 7.5b's design
doc itself (commit 3067c92 §6 Out of Scope) explicitly disclaims §14.1
invocation status: "framework infrastructure, not architectural commitment in
§14.1 sense; standard threshold applies." If future scope expansion makes §14.1
track non-ADR invocations (e.g., design-doc Phase 0 resolution locks),
Task 7.5b V4/V5 are eligible candidates.

---

## 2026-05-06 — Task 7.2 (Nmap as first DockerRunner consumer)

**Closes Task 7.2 engine-side per IMPLEMENTATION-PLAN.** Lands Nmap as the first
DockerRunner consumer per ADR-026 framework. Validates the framework against
real tool integration; establishes per-tool-task pattern for future Trivy +
SQLMap + ZAP + MobSF consumers. All 21 packages green under `go test -race
-count=1`; golangci-lint 0 issues.

### Entry 1: ADR-027 + cleanup-uses-parent-context promotion forward-pinned to Phase 5

ADR-027 "RawFinding.Metadata field for per-tool structured payload" is the
project corpus's 6th asymmetric-cost ADR (after ADR-022, ADR-023, ADR-024,
ADR-025, ADR-026). Lands in shieldscan-docs Phase 5 docs followup alongside
SPEC §7.3 RawFinding schema extension. ADR-027 was the load-bearing
architectural decision from Task 7.2 brainstorming Decision 1; ungrounded
in implementation reality at brainstorming time, now grounded in actual
nmap/parser.go RawFinding.Metadata population.

Cleanup-uses-parent-context anti-pattern hit 3rd instance per ADR-026
§Triggers-to-revisit #3. Instances:
  - M6.7 Wapiti file-output cleanup (1st)
  - ADR-026 DockerRunner.Run defer Pool.Return via context.WithoutCancel (2nd)
  - Task 7.2 runMain pool shutdown via context.Background() + 30s grace (3rd)

DEVELOPMENT-PATTERNS entry warranted; lands in Phase 5 alongside ADR-027.

### Entry 2: Schema extensions backward-compatible

ScanConfig gained two top-level fields per Task 7.2 Decision 2:
  - Ports string (Nmap-specific port range; "" or "top-1000" defaults to
    Nmap top-1000 behavior; explicit values like "80,443" or "1-65535"
    pass through to -p flag)
  - AllowPrivateTargets bool (defense-in-depth flag; defaults false;
    tenant-controllable for legitimate internal-network scanning with
    VPN/peered worker access)

RawFinding gained one field per Task 7.2 Decision 1 (and ADR-027 forward-pin):
  - Metadata map[string]string (per-tool structured payload; nil-safe
    nullable; json:"metadata,omitempty" tag for backward-compat with
    shieldscan-api findings-ingest consumer)

Section comment retitled `// Metadata` → `// Provenance + identity` to
disambiguate from the new Metadata field name.

All baseline tests preserved: 43/43 framework + M5/M6 native + events +
worker tests pass after schema extensions.

### Entry 3: Nmap parser captures CPE + Tunnel beyond Q6 minimalism

Phase 2 canonical-reference grounding (real Nmap 7.94 output via
instrumentisto/nmap:7.94 against scanme.nmap.org) revealed `<cpe>` child
elements + `<service tunnel="ssl">` attribute in actual Nmap XML output.
Per Phase 2 surface report direction:
  - CPEs []string field (xml:"cpe") added to nmapService; emitted as
    comma-joined metadata["cpe"] when non-empty (M9 CVE-matching
    forward-readiness)
  - Tunnel string field (xml:"tunnel,attr,omitempty") added; emitted as
    metadata["tunnel"] when non-empty (SSL-vs-cleartext semantic
    distinction; M9 finding correlation + M8 recon helper)

Asymmetric-cost meta-principle applied: ~10 LoC + 5 tests now vs M9 task
backfill + historical-data gap. Honors the 6th-ADR-instance pattern.

### Entry 4: 10 deviations across Phases 1-3 (verify-then-adapt-then-document)

Phase 1 (3 deviations):
  - stripPort IPv6 bug: verbatim's "no further colons after last" check
    incorrectly stripped bare ::1 to :. RFC4291 IPv6 has multiple colons;
    fixed by gating on strings.Count(addr, ":") == 1 (single-colon form
    rules out any IPv6 representation per RFC4291).
  - Multicast/link-local ordering bug: verbatim ordered IsLinkLocalUnicast
    before IsMulticast, but 224.0.0.1 is link-local-multicast per RFC5771
    (within 224.0.0.0/4 broader multicast space) — Go's
    IsLinkLocalMulticast() returns true; first-checked branch fired with
    wrong "link-local" rejection message. Fixed by reordering IsMulticast()
    first (catches 224.0.0.0/4 in full), then IsLinkLocalUnicast() only
    (cloud metadata at 169.254.169.254).
  - Test naming: TestValidateTarget_StripScheme/StripPort renamed to
    TestStripScheme/TestStripPort (helper-level scope; verbatim was
    misleading).

Phase 2 (1 deviation):
  - Removed unused strings import + sentinel from parser.go +
    parser_test.go. Verbatim included var _ = strings.TrimSpace as
    "future-use placeholder" — golangci-lint catches unused imports;
    YAGNI violation. Auto-cleaned. (Strings import re-added in Phase 3.1
    when CPE join required it.)

Phase 3 (6 deviations):
  - docker.NewProductionClient signature: verbatim assumed no-args
    constructor; actual takes *client.Client. Adapted: NewPool takes
    *dockerclient.Client and internally calls NewProductionClient,
    bridging unexported dockerClient interface boundary cleanly.
  - Registry frozen-at-construction: verbatim assumed
    registry.RegisterEngine(engine, runner) method exists; Registry is
    frozen-at-construction per docstring. Refactored: changed
    buildRegistry return type from (*Registry, ...) to
    (map[string]ToolRunner, ...) so caller can merge with
    buildDockerRegistry's runners before single worker.NewRegistry call.
  - docker.BuildArgsFunc type undefined: verbatim referenced this assumed
    named type for compile-time assertion; doesn't exist (BuildArgs is
    anonymous func field). Removed assertion; existing
    var _ tools.ToolRunner = (*DockerRunner)(nil) in dockerrunner.go
    covers framework-side compile-time check.
  - Missing tools import in nmap.go (buildArgsAdapter parameters); added.
  - Missing worker import in run_test.go (after buildRegistry signature
    change cascade); added.
  - Pool shutdown placement: verbatim suggested Startup.Shutdown method
    that doesn't exist; Startup is setup-only. Inverted: pool shutdown
    wired in run.go's drain path AFTER worker drain + heartbeat exit,
    using context.Background() + 30s grace (cleanup-uses-parent-context
    anti-pattern at 3rd instance).

Total: 10 factual deviations across Phases 1-3; zero architectural
deviations needing pause. Discipline pattern holds.

### Entry 5: New tracked patterns

Pattern: Stub testhelper replication across packages. Phase 3 replicated
stubDockerClient from internal/tools/docker/testhelpers_test.go to
internal/tools/docker/nmap/testhelpers_test.go (75 LoC). Go's structural
interface satisfaction allows the local stub to satisfy the unexported
docker.dockerClient interface without referring to the unexported name.
1st instance now; 3rd-instance promotion candidate is shared
internal/tools/docker/dockertest/ subpackage (when Trivy + SQLMap consumer
tasks land their own stub-backed tests).

Pattern: Adapter wrapper for framework signature mismatches. Phase 3
introduced two adapters in nmap.go:
  - buildArgsAdapter: bridges buildArgs error-return to DockerRunner
    no-error-return BuildArgs contract
  - parseOutputForDocker: bridges parseOutput stdout+target signature to
    DockerRunner stdout-only ParseOutput contract
1st instance now; if 2nd consumer (Trivy/SQLMap) needs same adapters,
consider DockerRunner framework signature changes (BuildArgs error return;
ParseOutput target propagation). Forward-pin documented in nmap.go
comments.

Pattern: Top-level tool-specific ScanConfig fields. TemplateCategories
(M6 Nuclei) + Ports + AllowPrivateTargets (M7.2 Nmap) all use top-level
field with documented tool-specificity vs ExtraArgs map (escape hatch).
2nd instance now; if 3rd consumer follows the same pattern, established
norm for project corpus.

### Entry 6: M7 task structure progress

  - Task 7.5a (warm pool + DockerRunner framework): CLOSED at f5d77c8
  - Task 7.5b (DockerServiceRunner): future; brainstorming + design + impl
  - Task 7.1 (Trivy): future; per-task brainstorm + DockerRunner consumer
  - Task 7.2 (Nmap): CLOSED engine-side (this commit); Phase 5 docs
    followup pending in shieldscan-docs
  - Task 7.3 (ZAP): future; depends on Task 7.5b
  - Task 7.4 (MobSF): future; depends on Task 7.5b
  - Task 7.6 (SQLMap): future; per-task brainstorm + DockerRunner consumer

### Entry 7: Forward-pins for future tasks

  - Phase 5 docs followup (shieldscan-docs):
    * ADR-027 (RawFinding.Metadata) lands in SPEC §13
    * SPEC §7.3 RawFinding schema extension documents Metadata field
    * DEVELOPMENT-PATTERNS entry for cleanup-uses-parent-context
      anti-pattern (3rd instance threshold met)
    * Task 7.2 design doc post-implementation alignment (mirrors a8e36a2
      pattern from Task 7.5a)
  - Future Trivy + SQLMap consumer tasks: leverage CPE + Tunnel
    metadata patterns; potential framework signature changes if
    BuildArgs error return + ParseOutput target propagation become
    cross-consumer needs
  - M9 AI Pipeline: CVE matching consumes Nmap CPEs + product+version
    from Metadata; severity escalation based on CVE matches
  - M8 Recon-First Pipeline: Nmap structured port/service/version/CPE
    metadata feeds downstream scanners (Nuclei, ZAP, SQLMap target
    list population)
  - Layer 4 network policy hardening (pre-launch infrastructure task):
    worker-host egress filtering + dedicated Docker network
  - SHIELDSCAN_INFRA_CIDRS env var: operator documentation when
    deployment infra lands
  - DNS rebinding mitigation: platform team forward-pin

---

## 2026-05-04 — Task 7.5a (Warm Pool Primitive + DockerRunner Framework)

**Closes Task 7.5a per IMPLEMENTATION-PLAN.** Lands warm pool primitive
(`internal/tools/docker/warmpool.go`) + DockerRunner framework type
(`internal/tools/docker/dockerrunner.go`) + Container Docker SDK
abstraction (`internal/tools/docker/container.go`) + comprehensive
test coverage (43 tests across 4 test files in
`internal/tools/docker/`). All 20 packages green under
`go test -race -count=1`; golangci-lint 0 issues.

### Entry 1: ADR-026 lands (5th asymmetric-cost ADR in project corpus)

ADR-026 "DockerRunner framework + lazy warm pool — M7 container
lifecycle architecture" is the project corpus's 5th ADR invoking
the asymmetric-cost meta-principle (after ADR-022, ADR-023,
ADR-024, ADR-025). The pattern is well-established norm; promotion
candidate to DEVELOPMENT-PATTERNS at next architectural decision-
point. ADR-026 full text lands in `shieldscan-docs/SPECIFICATION.md`
§13 separately (post-implementation per Mahmoud handling — see
Entry 7).

### Entry 2: Two-runner-type architecture confirmed (Option β resolution)

Per pre-design SPEC scan, ADR-006 + ADR-008 + SPEC §3 architecture
diagram explicitly specify two distinct Docker-tool runner types:
DockerRunner (CLI-shaped; warm pool) + DockerServiceRunner (HTTP-
shaped; persistent services). Brainstorming initially anticipated
all M7 tools using the warm pool; the SPEC scan caught this before
the design doc landed. Option β resolution preserved warm pool
primitive scope for CLI tools (Trivy, Nmap, SQLMap) while deferring
ZAP + MobSF to a future Task 7.5b DockerServiceRunner.

`internal/tools/runner.go` package docstring updated at this
commit to reflect actual M7.x consumer assignments (Trivy + SQLMap
moved from DockerServiceRunner to DockerRunner per Option β; the
previous docstring at runner.go lines 18-23 was stale pre-
brainstorming and listed Trivy + SQLMap under DockerServiceRunner).

### Entry 3: Lazy warm pool semantics

Pool starts empty; first checkout triggers spin-up; max-bound
prevents runaway resource usage. Resource floor is zero for unused
tools — customers running only SAST scans pay zero container cost
for the Trivy / Nmap / SQLMap pools. Pinned by
`TestWarmPool_Checkout_LazySpinUpOnFirstCall`.

### Entry 4: Cleanup hook contract + explicit NoCleanup

Per-tool `CleanupFunc` runs between checkouts to guarantee tenant
isolation (no state leak between scans). Stateless tools must use
exported `NoCleanup` explicitly — no nil functions allowed; New
returns an error if `cfg.Cleanup == nil`. Statelessness is
architecturally visible; future engineers reading per-tool
constructors see the explicit cleanup contract for every tool.

### Entry 5: 15 deviations across Phases 0-3 (verify-then-adapt-then-document discipline)

The verify-then-adapt-then-document discipline established during
M6-close-followup work continued to operate cleanly. Total 15
factual / mechanical deviations; **zero architectural deviations**
needing pause.

**Phase 0 (3 deviations):**
1. Docker SDK `+incompatible` versioning quirk (canonical Docker
   SDK module-system gap). Auto-document.
2. `internal/tools/docker_service.go` (M5.3 DockerServiceRunner) vs
   new `internal/tools/docker/` package conceptual overlap.
   Auto-document via package docstring on the new package.
3. `runner.go` package docstring stale (Trivy / SQLMap listed under
   DockerServiceRunner pre-Option-β). Fixed at Phase 4.

**Phase 1 (4 deviations):**
4. Docker SDK API drift v20.x → v28.5.2 substantial: 9 type
   relocations (`types.ImagePullOptions` → `image.PullOptions`;
   `types.ContainerStartOptions` → `container.StartOptions`;
   `types.ExecConfig` → `container.ExecOptions`;
   `types.ExecStartCheck` → `container.ExecAttachOptions`;
   `types.IDResponse` → `container.ExecCreateResponse`;
   `types.ContainerExecInspect` → `container.ExecInspect`;
   `types.ContainerRemoveOptions` → `container.RemoveOptions`;
   `v1.Platform` → `ocispec.Platform`; HijackedResponse adapter
   layer added). All verified via `go doc` against installed SDK.
5. `productionClient` adapter pattern added (`client_adapter.go`)
   to bridge `*client.Client` → package-local `dockerClient`
   interface. The interface returns package-local `HijackedResponse`
   (Reader + Close) for testability; production wraps the SDK type.
6. `testify v1.9.0 → v1.11.1` auto-bump (forced by OpenTelemetry
   transitives pulled in via Docker SDK) broke pre-existing
   `TestRunMain_HeartbeatRefreshesTTL` via `require.Eventually`
   callback semantics change in testify v1.11+. Refactored test to
   use plain bool returns inside `Eventually` (anti-pattern fix;
   project posture strictly better post-fix). Removed now-unused
   `findWorkerKey` helper.

**Phase 2 (3 deviations) — LOAD-BEARING CONCURRENCY BUGS IN VERBATIM:**
7. Verbatim `WarmPool.Shutdown` closed `available` channel; races
   with `Return`'s send-to-closed-channel and **panics**. Fix:
   separate `done chan struct{}` for shutdown signal; `available`
   never closed; `Shutdown` drains under mutex; closed-flag check
   + send atomic.
8. Verbatim blocking `Checkout` blocking-select didn't observe
   shutdown signal — silent nil-Container hazard if Shutdown
   closed `available` (which it doesn't post-fix-7, but the
   discipline applies). Fix: `<-p.done` in blocking-select. Pinned
   by `TestWarmPool_Shutdown_UnblocksWaitingCheckout`.
9. Verbatim health-check replacement size leak: `_ = c.Stop(ctx);
   p.size--; return p.spinUp(ctx)` — `spinUp` creates new
   container that should count in `size`, but the verbatim never
   re-incremented. Net effect: size leaks downward by one per
   replacement. Fix: replacement is **size-neutral on success**;
   `size--` only on `spinUp` failure.

**Phase 3 (5 deviations):**
10. Default timeout 30 min (matches `tools.DefaultNativeTimeout`);
    verbatim said 10 min.
11. 3-tier timeout precedence extracted to `effectiveTimeout(cfg)`
    method symmetric with `internal/tools/native.go:297`. Operator
    UX symmetric across NativeRunner + DockerRunner.
12. Finding enrichment loop honors ToolRunner contract per
    `runner.go` lines 65-69 docstring: ToolName / EngineCategory /
    DiscoveredAt / Fingerprint populated by the runner, NOT by
    ParseOutput. Mirrors `internal/tools/native.go:284-289`. Pinned
    by `TestDockerRunner_Run_ReturnsParsedFindingsEnriched`.
13. `context.WithoutCancel(ctx)` for `defer Return` cleanup avoids
    canceled-ctx-during-cleanup hazard. If Run hits its timeout,
    `runCtx` is canceled — but Return's cleanup hook still needs
    to run. Detached ctx with 30s grace bound. Matches the M6.7
    Wapiti file-output cleanup pattern (see Entry 6 below).
14. `stubDockerClient.ContainerExecAttach` returns
    `HijackedResponse{Reader: strings.NewReader("")}` — an empty
    valid Reader — instead of nil. `stdcopy.StdCopy(.., .., nil)`
    panics; the empty-reader fix prevents Phase 3 full-Run-path
    tests from panicking.

### Entry 6: New tracked patterns at 1st / 2nd instance

**Pattern: Cleanup-uses-parent-context anti-pattern (2nd instance).**
- 1st: M6.7 Wapiti file-output cleanup using parent ctx that hit
  timeout
- 2nd: M7.5a `DockerRunner.Run` defer Return — fixed via
  `context.WithoutCancel(ctx)` + 30s grace
- Track for 3rd-instance promotion to DEVELOPMENT-PATTERNS

**Pattern: Compile-time interface assertion (`var _ Iface = (*Type)(nil)`).**
- 1st: NativeRunner (`internal/tools/native.go:147`)
- 2nd: DockerRunner (`internal/tools/docker/dockerrunner.go`)
- Track for 3rd-instance promotion if reused for other framework
  types (e.g., DockerServiceRunner explicit assertion at Task 7.5b)

**Pattern: dockerClient interface boundary with productionClient
adapter for SDK testability (1st instance).**
- 1st: `internal/tools/docker/{dockerClient interface, productionClient}`
- Track for 3rd-instance promotion if reused for other SDK
  abstractions (AWS SDK, GCP SDK in future tasks)

### Entry 7: M7 task structure confirmed (7 tasks not 6)

The pre-brainstorming IMPLEMENTATION-PLAN listed 6 M7 tasks. Option
β resolution split Task 7.5 into 7.5a (this commit; warm pool +
DockerRunner) + 7.5b (future; DockerServiceRunner) — making M7 a
7-task milestone:

| Task | Scope | Runner type |
|---|---|---|
| 7.5a | Warm pool + DockerRunner framework (this task; **CLOSED**) | — |
| 7.5b | DockerServiceRunner framework (future) | — |
| 7.1 | Trivy (DockerRunner consumer; per-task brainstorm) | DockerRunner |
| 7.2 | Nmap (DockerRunner consumer; per-task brainstorm) | DockerRunner |
| 7.3 | ZAP (DockerServiceRunner consumer; per-task brainstorm) | DockerServiceRunner |
| 7.4 | MobSF (DockerServiceRunner consumer; per-task brainstorm) | DockerServiceRunner |
| 7.6 | SQLMap (DockerRunner consumer; per-task brainstorm) | DockerRunner |

ADR-026 + design doc revisions in `shieldscan-docs` follow post-
implementation (Mahmoud handles separately; see also adjustments
needed: §3.2 WarmPool code shape corrections from Phase 2 deviations
7-9; §6 Forcing functions section addition for done-channel
test pin; §6 Anti-patterns section additions for channel-close-as-
signal + decrement-without-increment-accounting; §9 Phase 2 design-
doc concurrency-bug acknowledgment).

---

## 2026-05-03 — SPEC §7.3 Phase 4 (cross-repo verification — task closed)

**Phase 4 closes M6-close-followup task.** Cross-repo
verification confirms:

1. **Engine omitempty serialization end-to-end.** RawFinding with
   nil/empty new fields serializes to JSON without the 4 new
   field keys (verified via `TestRawFinding_NewFieldsOmitemptyWhenAbsent`
   in `internal/events/events_test.go`).

2. **Reductions counter post-§7.3 status confirmed.** 6 tools
   populate new fields (Nuclei, Semgrep, Gitleaks, Dep-Check,
   Checkov, Wapiti); 3 tools intentionally untouched (SSLyze,
   Nikto, CORStest per ADR-024 §3.4 — `grep` confirms zero
   References/Tags/CVSSVector/AdditionalCWEs references in their
   parsers). 8/9 tools (89%) still have reductions; ~26 folds
   remaining (down from ~38). Trigger remains fired per ADR-024
   §3.5 for future incremental schema extensions.

3. **Alembic migration roundtrip reconfirmed.** Forward + backward
   + forward at Phase 4 close; head at `49e83eb3587c`.

4. **SQLAlchemy model tests still green.** 20/20 in
   `tests/models/test_findings.py`.

5. **Engine full repo green.** All 19 packages pass `go test
   -race -count=1 ./...`; `golangci-lint` 0 issues; `go vet`
   clean; `gofmt -l internal/ cmd/` clean.

**M6-close-followup task closed.** Cross-repo commit chain:

| Phase | Repo | Commit | Description |
|-------|------|--------|-------------|
| 1a | shieldscan-docs | `59b0f3d` | ADR-024 + SPEC §7.3 + design doc + DRIFT entries |
| 1b | shieldscan-docs | `8f90531` | ADR-024 verbatim alignment fixup (4 sections) |
| 2 | shieldscan-api | `938ae80` | SQLAlchemy 4 columns + Alembic `49e83eb3587c` |
| 3 | shieldscan-engine | `8fbd085` | RawFinding 4 fields + 6-tool retrofit + CVSS mapping + jsonx 7th helper |
| 4 | shieldscan-engine | (this DRIFT entry) | Cross-repo verification close |

**M6-close-followup outcomes:**

- 4 fields land: References, Tags, CVSSVector, AdditionalCWEs.
- ~12 fold rescues across 6 tools (~32% of pre-§7.3 reductions).
- ADR-024 lands as M6's 3rd ADR (after ADR-022 recon-as-helpers
  + ADR-023 NativeRunner OutputFile).
- jsonx promoted to 7 helpers (`FilterEngineCategoryTags` 7th
  helper added during Phase 3; clean 3-instance promotion
  threshold met within the Phase).
- 2 new tracked patterns at 1st instance:
  - Multi-repo schema-coordination commits (Phase 1+2+3 strict
    order)
  - Optional-field additive migrations with backward-compat
    (Alembic + Go omitempty)
- Asymmetric-cost meta-principle 3rd invocation in project
  corpus (after ADR-022, ADR-023).
- Phase 0 verification pattern reinforced (3rd instance after
  M6.6 Nikto stdout, M6.3 httpx stdin).

**Load-bearing forward-pins for M9:**

- §8.2 cross-layer correlation algorithm: must extend
  `cwe_exact` + `cwe_parent` checks to consider intersection with
  `additional_cwes` (per ADR-024 §3.1.4 + Phase 3 DRIFT entry 5).
- §8.3 exploitability_multiplier derivation: CVSSVector reserved
  for future direct AV/network parsing (replacing separate
  publicly-accessible detection logic; per ADR-024 §3.1.3).

**Triggers remaining open:**

- Trigger remains fired (8/9 tools still have reductions);
  future incremental schema extensions may address tool-specific
  metadata when M7+ data informs which patterns warrant
  first-class fields (per ADR-024 §3.5 + trigger #3).
- Findings-ingest task (M4-completion or M9-prerequisite) lands
  Pydantic schema + CompletionsConsumer extension + ingest tests
  per ADR-024 trigger #6. Schema columns from Phase 2 are
  already in place.

**Next directions (per Mahmoud's choice):**

- M7 Docker service tools (landscape pass needed)
- OPS milestone (`provision-worker.sh` consolidation)
- Findings-ingest task (closes ADR-024 §3.2 columns-ready
  posture)

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
