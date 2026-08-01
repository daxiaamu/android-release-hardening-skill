# Integration patterns

## Gradle and signing

- Keep `keystore.properties`, JKS/PKCS12 files, passwords, DER exports, mapping files, and native symbols out of source control.
- Resolve signing material from the project's secure environment. Fail the release build when required properties are missing.
- Export only the public signing certificate DER/SHA-256 needed to generate trust anchors.
- Verify the final artifact after signing; do not validate only an unsigned/intermediate APK.
- For AAB delivery, distinguish the upload certificate from the Play app-signing certificate. Pin the certificate that signs installed APKs.

## Android signer APIs

For API 28+, use `GET_SIGNING_CERTIFICATES` and inspect `SigningInfo`. Define whether signing lineage is accepted. Reject unexpected multiple current signers unless the application intentionally uses multi-signing. For older APIs, use the deprecated signatures array only as a compatibility path.

Treat PackageManager results as one evidence source. A repackager can patch Java call sites or hooks can alter results.

## Direct APK parsing

Resolve `ApplicationInfo.sourceDir` and parse the final installed base APK. Validate ZIP central-directory boundaries before walking backward to the APK Signing Block. Parse length-prefixed v2/v3 signer structures defensively, reject duplicate/ambiguous fields, and hash the exact DER certificate bytes.

Use a maintained parser when available. If implementing a minimal parser, fuzz malformed lengths and confirm behavior against `apksigner verify`.

## JNI boundary

Keep JNI methods few and make them participate in a graph rather than return a single patchable boolean. Register native methods dynamically when appropriate, but do not rely on renamed symbols alone. Validate exceptions after reflective/JNI calls and fail closed only for protected features.

Compile native code separately per ABI. Verify that every ABI receives the same generated trust profile and self-seal procedure.

## Build diversification

Generate a profile for every release build containing:

- public build ID;
- operation identifiers;
- layout permutation and style parameters;
- watchdog interval range;
- payload salt and non-secret VM program seed;
- trust-profile version.

Persist the profile privately with the release evidence so crashes and regressions can be reproduced. Randomization is diversification, not cryptographic secrecy.

## UI sealing

Create protected text only after capability validation. Retain the complete expected scene in trusted/native state and bind:

- text values;
- view count and order;
- visibility/enabled/clickable state;
- selected dimensions/colors/typeface properties;
- current challenge and proof;
- build ID and lifecycle phase.

Recheck after initial layout and periodically. Use tolerance for density-dependent measurements and accessibility-driven changes; otherwise legitimate devices will false-positive.

## Compatibility

Test at least the minimum API, a current API, 32/64-bit ABIs if shipped, OEM-skinned Android, split-install behavior, upgrades signed by the official lineage, and accessibility/font-scale changes. Make hardening observable in internal diagnostics without leaking trust anchors or bypass switches in release builds.

For artifact-shell mode, separately test ordinary Activity, custom Application identity, startup providers, NativeActivity/JNI lookup, multi-DEX, each emitted ABI, cold/warm start, and upgrade install. The payload class loader must carry `ApplicationInfo.nativeLibraryDir`. If a framework component must load before the shell can install the payload loader (for example a custom AppComponentFactory), reject or explicitly downgrade support in preflight.
