# Vibe Hermes Inspector v0.2 — release-signing preparation

The verified binary in Draft PR #34 is a **DEBUG** APK, signed with a temporary CI debug certificate. Every fresh hosted runner can generate a different debug certificate.

## Consequence for v0.1 → v0.2

Debug builds signed on different CI runners generally **cannot be installed in place** over an existing installation with the same applicationId. Android will report a signing-certificate mismatch. Do not try to disable Android signature checks. Uninstall the older debug APK before installing the newer debug APK, after preserving any information you need.

## Permanent update-compatible release signing

The Gradle project supports optional release signing with externally supplied environment variables:

- \`VIBE_RELEASE_KEYSTORE_FILE\`: absolute filesystem path to a private keystore, injected by CI or local shell
- \`VIBE_RELEASE_STORE_PASSWORD\`: keystore password
- \`VIBE_RELEASE_KEY_ALIAS\`: key alias
- \`VIBE_RELEASE_KEY_PASSWORD\`: alias key password

Generate and securely back up a unique keystore **privately**, not under this public repo:

\`\`\`sh
keytool -genkeypair -v -keystore vibe-release.jks -storetype PKCS12 \
  -alias vibe-release -keyalg RSA -keysize 4096 -validity 10000
\`\`\`

Back up both the encrypted keystore and credentials off-device in trusted, access-controlled storage. To build a release APK with a consistent signing identity, supply the same keystore/alias/passwords on each release. Never commit them to source, print them in CI logs, or upload unencrypted keys as public build artifacts.

\`\`\`sh
# Example: Environment variables must already be securely injected.
gradle -p android/hermes-inspector verifyReleaseSigning assembleRelease
\`\`\`

The Gradle release gate refuses release assembly when any required signing information is missing. The default APK build workflow deliberately builds a **debug** artifact only, and does not require secrets or change the repository billing configuration.

## Unverified release gates

- No private release keystore has been supplied or configured in the connected GitHub account.
- An actual consistently signed release pair has not been produced.
- In-place upgrade compatibility has not been physically tested.
- Do not claim a public release or production readiness based solely on the debug APK.

Other app data is private, Android network permission is absent, SAF imports are read-only, and exported JSON is explicitly directed by the user.
