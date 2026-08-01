# Layered architecture

## Trust graph

Use independent evidence domains and make protected output depend on their agreement:

1. **Platform signer path**: `PackageManager`, `SigningInfo`, current and historical signers, single-signer policy.
2. **Artifact signer path**: open the installed `sourceDir`/`base.apk`; parse the active APK Signing Block v2/v3 signer and compare the leaf certificate digest.
3. **Legacy anchor path**: where v1 is shipped, verify `META-INF` certificate fragments/JAR entries independently. Do not confuse v1 presence with overall APK integrity.
4. **Runtime artifact path**: compare canonical APK path, stat device/inode/size, and loaded library mappings from `/proc/self/maps`; validate critical SO self-seals.
5. **Business-state path**: issue a native capability only after all required evidence agrees; consume it when creating protected data and rendering UI.
6. **View-state path**: retain references to all protected views, seal expected text/order/style/visibility, and recheck them throughout foreground lifetime.

Avoid returning one reusable boolean. Prefer an opaque process-local capability containing generation, challenge binding, phase, and a MAC derived from per-build sealed material. Clear it on failure and lifecycle transitions requiring revalidation.

## Suggested components

- `IntegrityApplication`: early initialization and lifecycle callbacks.
- `IntegrityWatchdog`: background scheduling and foreground rechecks.
- `IntegrityBridge`: minimal stable JNI surface; keep operation names generated per build where practical.
- `libanchor`: independent signer/runtime anchor with its own self-seal.
- `libengine`: verification graph, sealed payload, capability issue/consume, and View-state checks.
- `TamperActivity`: primary non-cancelable failure surface.
- `EmergencyActivity`: independently implemented fallback surface.
- Application-owned repair path: validate that a real dialog/button exists; repair a short-circuited failure Activity.

Keep failure classes manifest-reachable and explicitly preserved by R8. Test the produced DEX to ensure native-only class references were not removed.

## Native self-seal

At build time:

1. Compile with hidden visibility, RELRO, NOW binding, stripped symbols, and platform-supported control-flow protection.
2. Reserve a unique fixed-size marker plus zero digest slot in a read-only section.
3. Hash the completed SO with the digest slot zeroed.
4. Patch the digest into the slot without changing file size.
5. At runtime locate the actual loaded file, zero the slot logically while hashing, and compare in constant time.

A self-seal is a tamper signal, not a secret. Cross-bind two libraries so replacing only one invalidates the capability graph.

## Sealed payload

Store protected scene strings, build identifiers, capability keys, and non-secret program data in an encrypted/authenticated payload. Derive the unwrap key from the expected signer digest, independent anchor output, and per-build salt. Authenticate before use and wipe temporary cleartext where feasible.

Do not embed server private keys, keystore passwords, API master secrets, or reusable credentials.

## Failure behavior

On any required-check failure:

- Atomically revoke capabilities.
- Prevent protected content creation or remove already rendered protected state.
- Route to a dedicated failure task/surface.
- Set `FLAG_SECURE` if screenshots are outside the test protocol.
- Disable Back and outside cancellation.
- Provide one explicit Exit action that removes the task and terminates the process.
- Recheck that the failure dialog is actually showing; invoke an independently owned fallback if it is not.

Never delete user data, damage the device, block package management, or affect other applications.

## Limits

Root and arbitrary code modification give the attacker control over the local execution environment. These controls raise analysis/maintenance cost and detect tested mutation classes; they cannot create an absolute offline trust boundary. Put high-value authorization and mutable policy on a server when the product permits it.
