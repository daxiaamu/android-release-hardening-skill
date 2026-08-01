# Release gate and attack matrix

## Baseline gate

Require all of the following before adversarial testing:

- Release build is non-debuggable, backup policy is intentional, and cleartext/network policy is intentional.
- R8 mapping and native symbols are stored privately for support; neither is packaged.
- Final APK verifies with the expected certificate SHA-256 and required v1/v2/v3 schemes.
- Fresh install and upgrade paths both work.
- At least five newly generated challenges produce distinct valid protected outputs.
- Cold start, resume, configuration change, background/foreground, and 15-second dwell preserve valid state.

## Static mutation corpus

Generate each sample from the final APK, sign with an attacker test key, record SHA-256, and change one variable first:

1. Rebuild/re-sign without source changes.
2. Remove or replace the custom Application.
3. Short-circuit Application initialization.
4. Short-circuit each signer/integrity wrapper.
5. Patch each primary and fallback failure Activity separately.
6. Patch all failure Activities together.
7. Patch Application plus all failure Activities.
8. Remove/replace watchdog scheduling.
9. Change protected strings/resources/layout order/style.
10. Modify one byte in each critical SO independently.
11. Replace each SO with a stub exposing compatible JNI names.
12. Change manifest entry points, aliases, task flags, and exported state.
13. Replay a prior build's DEX/resources/SO into the current package.
14. Fix the challenge/proof output to values from a prior run.
15. Expand a business ELF `PT_LOAD`, move the section table, embed captured plaintext/keystream, and re-sign.
16. Recompute a modified business SO's internal self-seal while leaving the outer shell unchanged.
17. Patch only one device ABI while retaining pristine libraries for the other shipped ABIs.
18. Dump the runtime-loaded business DEX, restore the original Application/launcher, remove every shell class/provider/asset/SO/metadata entry, and rebuild an attacker-signed standalone APK.
19. In the peeled APK, patch business signer/self-seal gates while leaving the real challenge/proof computation intact; verify that newly generated challenges cannot match the official build.
20. Add a peeled-package facade that returns fixed, zero, random, or replayed outer shares; require fresh proof/scene/view-seal mismatch and the prescribed failure UI where the business layer can authenticate the share.
21. Patch the outer-share Java facade while leaving both shell SOs unchanged; require shell DEX measurement or the native graph to reject it.
22. Extract only one shell SO and attempt to emulate the share protocol; verify the complementary fragment is required for every challenge/domain.
23. Search all packaged ELFs for descriptive self-seal markers and verify per-build marker diversification across two consecutive builds.

After single mutations, create evidence-driven combinations of two to four controls. Do not enumerate arbitrary combinations without a demonstrated dependency graph.

## Runtime corpus

On an explicitly authorized root test device, test:

- PackageManager/SigningInfo return substitution.
- File open/read/stat and `/proc/self/maps` substitution.
- JNI method return or registration replacement.
- Activity routing suppression.
- View text/order/style replacement after initial rendering.
- Watchdog sleep/thread interruption.
- Capability replay across challenge, phase, process, or build.
- Plaintext/payload extraction after official startup followed by replay in an attacker-signed build.
- Business SO replacement while shell SOs and shell DEX remain unchanged.
- Runtime DEX extraction followed by complete shell deletion and inner-APK reconstruction.
- Removal of the outer capability producer while replaying or locally emulating its last observed output.

Keep hooks narrow and reproducible. Save scripts and exact framework/module versions.

## Pass/fail

**Protected success** requires the expected official build title, exact fresh challenge, correctly formatted proof bound to that challenge, live view seal, and stable foreground behavior.

**Defense success** requires a visible non-cancelable failure dialog, persistence after Back and outside touch, only one Exit action, and no usable protected content behind it.

Crash, silent exit, blank screen, wrong challenge, stale proof, or a failure Activity without the required dialog is a regression—not a defense pass.

## Evidence bundle

For every case save:

- device serial/model/API/root state;
- input APK path and SHA-256;
- mutation name and exact diff/script;
- install/start commands with `adb -s`;
- challenge and expected classification;
- UI XML before and after Back/outside touch;
- resumed Activity/window state;
- focused logcat slice;
- machine-readable result JSON and concise Markdown table;
- confirmation that the official APK was restored.

Never operate an unselected device when multiple ADB devices are connected.
