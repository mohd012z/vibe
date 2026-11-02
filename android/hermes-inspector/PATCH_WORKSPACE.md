# Vibe APK Patch Workspace v0.7.0

## Scope
Offline, staged non-executable text-resource edits for APKs owned by the user or authorized for modification. The app does not disable third-party subscription, payment or security controls.

## Workflow
1. Import an APK using Android's document picker.
2. Browse its source and packaged files. Open a supported text file and edit a local copy.
3. Compare the diff and stage the selected text-asset edit.
4. Optionally run automated exact literal replacement on eligible text assets. Batch staging is transactional.
5. Review up to twelve staged assets with original and replacement SHA-256 evidence. Clear the plan to discard changes.
6. Export a NEW unsigned APK. The original is never overwritten.

## Editing limits
Only valid UTF-8, non-executable text under assets/ or res/raw/ with supported text extensions is accepted. Each entry is limited to 64 KiB, twelve staged assets maximum; dangerous ZIP paths, duplicates, malformed UTF-8, excessive expanded sizes and unsafe compression ratios are rejected.

JavaScript executable bundles, DEX, native machine code, Hermes bytecode, AndroidManifest.xml, compiled resource tables and signature files cannot be staged. Original source SHA-256 is checked before modification. The output ZIP is SHA-256 verified and atomically renamed inside app-private storage before Android document-provider export.

## Signing
A repacked APK is UNSIGNED and NOT ZIPALIGNED. It is not installable until independently aligned and signed with a legitimate, authorized key. Android does not permit in-place upgrades when certificates differ. The app does not claim to preserve another developer's APK signing identity.

## Recovery and limitations
Staged changes are in memory; discard them to reset. The original APK remains intact. Cached APK files are deleted at normal app close and stale inspector cache files are removed after restart. Export via a third-party Android document provider is not atomic; a failed provider write may leave a partial file, which should be deleted. Real-phone acceptance, memory stress and stable release-key setup remain separate release gates.

No networking, subscription bypass, production merge or billing configuration is included.
