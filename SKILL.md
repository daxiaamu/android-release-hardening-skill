---
name: android-release-hardening
description: Harden Android applications before release with layered APK signer verification, native integrity anchors, capability-gated business logic, continuous runtime checks, resilient failure surfaces, per-build diversification, and automated tamper regression. Use when Codex needs to assess or modify an Android/Gradle/NDK project before publishing, add anti-tamper or anti-repackaging controls, validate a signed APK, build a release hardening checklist, or create a reproducible red-team corpus for an authorized app.
---

# Android Release Hardening

Apply defense in depth to the source project, then prove behavior on the final signed APK. Do not treat any single certificate check, obfuscator, or native library as sufficient.

## Workflow

1. Establish inputs:
   - Project root, application ID, release variant, supported ABI/API levels.
   - Final signing certificate SHA-256; never copy keystores or passwords into the skill or reports.
   - Build command, output APK/AAB, dedicated test-device serial, and acceptance rules.
2. Run `scripts/audit_android_project.py <project> --out <dir>` and inspect both JSON and Markdown results.
3. Read `references/architecture.md`; select controls that fit the project rather than blindly copying every mechanism.
4. Implement one layer at a time, keeping a reversible diff. Preserve application behavior before adding the next layer.
5. Generate per-build non-secret diversification material with `scripts/generate_build_profile.py`. Feed it through generated source/build config; never use it as a substitute for cryptographic secrets.
6. Build the release artifact with the project's official toolchain and signing configuration.
7. Run `scripts/verify_apk.ps1` against the final APK. Require the expected certificate digest and required signing schemes.
8. Build attack variants and run the matrix in `references/release-gate.md` on an explicitly selected device (`adb -s <serial>` only).
9. Validate success at the authoritative UI/business-state surface. Save APK hashes, commands, UI hierarchy, current Activity, logcat, and result JSON.
10. Report implemented controls, exact evidence, remaining bypass classes, and rollback paths. Never claim an offline client is unbreakable.

## Required design rules

- Bind protected business output to a short-lived capability produced only after integrity validation; do not merely call `if (!valid) exit()` beside otherwise reachable business code.
- Cross-check signer identity through at least two independently implemented paths. Prefer PackageManager/SigningInfo plus direct parsing of the installed base APK; add v1/JAR or raw Binder checks only when compatible.
- Validate the installed artifact, loaded native mappings, and critical UI/business state continuously at randomized or build-specific intervals.
- Keep trust anchors split across independently built components. Seal critical native files and verify the seal before using decrypted payloads.
- Generate protected strings/layout parameters only after capability validation. Verify the complete rendered state, not one title string.
- Implement at least two independent failure surfaces plus a third repair/verification owner. Failure UI must be non-cancelable, reject Back/outside touches, and expose only Exit.
- Vary build identifiers, operation names, salts, layout topology, and non-secret VM parameters per release. Keep protocol compatibility explicit.
- Make failure closed for protected features, while avoiding destructive behavior, boot loops, or interference with unrelated apps.
- Keep release signing outside source control. Pass secrets via the existing secure build environment and redact command output.

## Evidence hierarchy

Prefer final-device behavior, captured runtime state, final APK contents/signatures, and build configuration over comments or source intent. A parser difference is not a defense result until the protected feature is actually blocked and the required failure surface is verified.

## References

- Read `references/architecture.md` for the code-level component blueprint and implementation choices.
- Read `references/release-gate.md` before building attack samples or defining pass/fail criteria.
- Read `references/integration-patterns.md` when adapting controls to Java/Kotlin, JNI, Gradle, APK, or AAB projects.
