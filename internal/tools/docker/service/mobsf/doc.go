// Package mobsf provides the MobSF (Mobile Security Framework) MAST
// consumer for the Task 7.5b DockerServiceRunner framework
// (commit 1306ca8).
//
// MobSF is a static + dynamic mobile application security testing tool
// (MAST: Mobile Application Security Testing). This v1 consumer
// implements STATIC analysis only — dynamic + source-tree analysis are
// forward-pinned (Task 7.4 design doc §3.1 Path Y).
//
// Two scan flavours per Q2(iv) lock (file-extension validated by
// target.go):
//   - Android: .apk / .xapk / .aab
//   - iOS:     .ipa
//
// REST API contract (per Phase 0 V1-V18 grounded reality; verbatim
// against MobSF v4.4.6 digest sha256:72311e3553ca2c21043923cace27ed99
// f800cd641e9368160406779516dd774e):
//   - POST /api/v1/upload                 — multipart APK/IPA upload
//   - POST /api/v1/scan                   — sync static-analysis trigger
//   - POST /api/v1/report_json            — fetch structured report
//   - POST /api/v1/delete_scan            — Task 7.5d analogue cleanup
//
// Auth: X-Mobsf-Api-Key header (verified at Phase 0 V3).
//
// Ships with cfg.EphemeralContainer = true v1 default per Q5 Option β
// + Task 7.5b V4 Option γ precedent — delete_scan idempotency-across-
// surfaces verification deferred to Task 7.5d analogue of Task 7.5c.
//
// Cross-references:
//   - shieldscan-docs commit 02be8cf (Task 7.4 design doc)
//   - shieldscan-docs commit 4a94c2e (Task 7.4 implementation plan)
//   - shieldscan-engine commit 1306ca8 (Task 7.5b framework)
//   - SPECIFICATION.md §13 ADR-008 (MobSF persistent service legacy;
//     Phase 5.B addendum target)
//   - SPECIFICATION.md §13 ADR-026 (DockerServiceRunner architecture)
//   - SPECIFICATION.md §13 ADR-027 (RawFinding.Metadata schema)
package mobsf
