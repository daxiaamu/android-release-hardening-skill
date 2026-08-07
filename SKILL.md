---
name: android-release-hardening
description: Harden Android applications before release with layered APK signer verification, native integrity anchors, capability-gated business logic, continuous runtime checks, resilient failure surfaces, per-build diversification, and automated tamper regression. Use when Codex needs to assess or modify an Android/Gradle/NDK project before publishing, add anti-tamper or anti-repackaging controls, validate a signed APK, build a release hardening checklist, or create a reproducible red-team corpus for an authorized app.
---

# Android Release Hardening

Choose one of two explicit integration modes, then prove behavior on the final signed APK:

- **Source mode** modifies an Android/Gradle/NDK project with project-aware controls.
- **Artifact-shell mode** takes a final standalone APK, runs the reusable DXProtect tool, and does not modify business source.

Do not silently substitute a demo application for artifact-shell mode. Do not treat any single certificate check, obfuscator, or native library as sufficient.

## Workflow

1. Establish the requested mode and inputs:
   - Project root, application ID, release variant, supported ABI/API levels.
   - For artifact-shell mode: standalone input APK, protected output APK, DXProtect config/tool root, and compatibility requirements.
   - Final signing certificate SHA-256; never copy keystores or passwords into the skill or reports.
   - Build command, output APK/AAB, dedicated test-device serial, and acceptance rules.
2. In source mode, run `scripts/audit_android_project.py <project> --out <dir>` and inspect both JSON and Markdown results. In artifact-shell mode, run DXProtect preflight and inspect `compatibility_preflight` in the output report.
3. Read `references/architecture.md`; select controls that fit the project rather than blindly copying every mechanism.
4. Implement one layer at a time, keeping a reversible diff. In artifact-shell mode, leave business source untouched and change only the output artifact/tool configuration. Preserve application behavior before adding the next layer.
5. Generate per-build non-secret diversification material with `scripts/generate_build_profile.py`. Feed it through generated source/build config; never use it as a substitute for cryptographic secrets.
6. Build the release artifact with the project's official toolchain and signing configuration. For artifact-shell mode, build the official APK first and then invoke `dxprotect.ps1 -Config <secure-config>`.
7. Run `scripts/verify_apk.ps1` against the final APK. Require the expected certificate digest and required signing schemes.
8. Build attack variants and run the matrix in `references/release-gate.md` on an explicitly selected device (`adb -s <serial>` only).
9. Validate success at the authoritative UI/business-state surface. Save APK hashes, commands, UI hierarchy, current Activity, logcat, and result JSON.
10. Report implemented controls, exact evidence, remaining bypass classes, and rollback paths. Never claim an offline client is unbreakable.

## Artifact-shell requirements

- Accept a standalone APK as input and emit a new protected APK plus a machine-readable report; never require or rewrite business source unless the user separately requests source mode.
- Preserve original native libraries and ABI coverage. Ensure the in-memory/DexClassLoader native search path includes the original `nativeLibraryDir`.
- Restore a custom original Application as the framework-visible identity before business providers/activities rely on it; validate this with a fixture that casts `getApplication()` to the original type.
- Preserve the resolved launcher theme, task/window attributes, and exact MAIN/LAUNCHER filter on the shell gateway. On Android 12+, retain the system splash until the original Activity covers the gateway; clone the complete source Intent rather than rebuilding only action/extras, then strip launcher-only root-task routing flags for the internal handoff.
- Resolve `activity-alias` launchers through `targetActivity`. Reject multiple launcher components until their enable/disable and dynamic-icon semantics can be preserved; never silently collapse them to one entry.
- Reject unsupported early-loading structures such as a custom `appComponentFactory` rather than emitting a likely-crashing APK.
- Keep per-build Java classes, native methods, JNI registration protocol, SO names, asset paths, metadata keys, watchdog interval, payload keys, and failure identifiers diversified.
- Inspect the final ELF symbol/string surface. Source-level XOR does not count if compiler constant folding recreates plaintext; verify the packaged SO files.
- Bind the shell `classes.dex` digest into the native verification graph and verify it directly from the installed APK.
- Enumerate every original business SO before injecting shell libraries. Embed an obscured entry/digest manifest and remeasure each original SO directly from the installed APK during startup and watchdog checks.
- Treat long-lived decrypted payloads as a regression risk. Prefer challenge/phase-scoped material, wipe native buffers immediately after use, and use process/epoch-bound capabilities rather than stable authorization booleans.
- Treat shell removal as a first-class attack. The extracted business DEX plus original Manifest/business SOs must not remain a runnable standalone APK. Make protected output depend on an outer-owned share at multiple computation points; do not use the shell only as a startup gate or disposable file verifier.
- Split anti-peel share material across independently built shell libraries. Have one library verify the cross-sealed graph and emit a challenge/phase/domain fragment, then require the second library to combine that fragment with its own secret and the measured business graph. Do not place both share secrets in one generated header or one SO.
- Mix multiple fresh outer shares into initial state, iterative business computation, final output, rendered-state seal, and watchdog state. A peeled package with a fixed/null facade must produce neither the official proof nor an accepted protected state.
- Do not let the measured graph collapse to a boolean. Produce a full-width graph state from actual signer, shell DEX, shell SO, business SO, capability, and runtime measurements; mix that state into every outer-share derivation. A patched success return that does not also reproduce the state must poison protected output.
- Bind rendered text and layout to the externally compared seal. Replacing a title after proof calculation must change the View seal or invalidate the next watchdog epoch.
- Use per-build random binary self-seal markers. Reject descriptive marker strings such as `ENGINEHASH`, which become stable reverse-engineering anchors.
- Test the exact peeled reconstruction: recovered business DEX, restored original Application/launcher, original resources, patched business SOs, and attacker signing. Reject a release if fresh protected outputs still work after the shell classes, assets, metadata, providers, and SOs are deleted.
- Sign to a temporary artifact, verify signature and structure, then atomically publish the output so a failed run cannot replace a known-good release.

## Bundled DXProtect tool

The reusable artifact shell is bundled under `scripts/dxprotect/`. Read `references/dxprotect-tool.md` before use. Copy `scripts/dxprotect/dxprotect.config.example.json` to a secure project-external location, fill in the target/release toolchain paths, set only the named password environment variables, and run `scripts/dxprotect/dxprotect.ps1 -Config <config>`.

Do not edit the target application's source in artifact-shell mode. Do not use the bundled fixture/test keys for a user release. The scripts `mutate_dex_string.py`, `mutate_apk_dex_string.py`, and `mutate_payload.py` are only for authorized tamper-regression samples after a clean protected baseline exists.

## Required design rules

- Bind protected business output to a short-lived capability produced only after integrity validation; do not merely call `if (!valid) exit()` beside otherwise reachable business code.
- Cross-check signer identity through at least two independently implemented paths. Prefer PackageManager/SigningInfo plus direct parsing of the installed base APK; add v1/JAR or raw Binder checks only when compatible.
- Validate the installed artifact, loaded native mappings, and critical UI/business state continuously at randomized or build-specific intervals.
- Keep trust anchors split across independently built components. Seal critical native files and verify the seal before using decrypted payloads.
- Verify the packaged output actually preserves secret separation: the engine SO contains only its share and the anchor SO contains only the complementary share for every ABI.
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
- Read `references/dxprotect-tool.md` before artifact-shell mode; it documents the bundled APK input/output contract, configuration, compatibility boundary, and release evidence.
