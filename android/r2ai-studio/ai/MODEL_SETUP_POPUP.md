# Android phone-first model setup popup

**Trigger:** AI Chat opened and no local model loaded.

**Title:** Offline AI model required

**Message:** Vibe Studio's editor and APK inspector work without an AI model. For private AI chat, import a compatible LiteRT-LM model file (`.litertlm`). GGUF is not required.

**Actions:**
1. **Import model** — ACTION_OPEN_DOCUMENT with MIME application/octet-stream; verify extension as a hint, copy to app-private files directory, check available storage, show progress, and validate with engine initialization.
2. **View compatible models** — https://huggingface.co/litert-community (external browser; user approves download).
3. **Continue without AI** — return to read-only inspector and editor.
4. **Settings** — AI Models → Import / Remove / Retry / Diagnostics.

**On failure:** Show exception category, user-readable explanation, copyable diagnostic (without file contents or secrets), Retry, and Continue without AI.

**Privacy:** No automatic network requests or silent file uploads.
