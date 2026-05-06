# Changelog

## 0.7.0 (2026-05-06)

### Added
- **Markdown → Threema-Markup conversion** for all outbound text. Threema natively supports `*bold*`, `_italic_`, and `~strikethrough~` since 2024 — but does NOT understand standard Markdown (`**bold**`, `# headers`, `- lists`, `[links](url)`, code fences, tables). The plugin now transparently converts Markdown into Threema-compatible markup before sending, so agent replies look correct in the Threema client without any prompt changes.
  - New module: `markdown-to-threema.ts` (with full unit-test suite, 23/23 passing).
  - Conversions:
    - `**bold**` / `__bold__` → `*bold*` (Threema bold)
    - `~~strike~~` → `~strike~` (Threema strikethrough)
    - Single-asterisk `*x*` and underscore `_x_` left untouched.
    - `# / ## / …` headers → `*Header*` (bold).
    - `- / * / +` lists → `•` (Unicode bullet).
    - Numbered lists kept as-is (Threema renders them fine plain).
    - Blockquotes (`>`) → `│` (vertical bar).
    - Pipe-tables → bullet-list with bold headers (`• *Header:* value`).
    - Inline code `` `x` `` → `"x"`. Fenced code blocks → plain content, fences stripped.
    - Links `[text](url)` → `text — url` (or just `url` when text == url).
    - Markdown images `![alt](url)` → `[Bild: alt] — url`.
    - Horizontal rules → unicode line.
  - Hooked into all outbound paths: `outbound.sendText` adapter (cron / message-tool delivery), inbound text-reply callbacks (multi-chunk, voice fallback, regular DM replies), and inbound file-reply caption handling.
  - Runs idempotently — valid Threema-already markup passes through unchanged.

### Notes
- Behaviour change: previously, agent replies containing Markdown looked unrendered in Threema (literal `**`, `##`, `|`). Now they render with Threema’s native bold/italic/strikethrough wherever possible. Plain text and existing Threema markup are unaffected.

## 0.6.7 (2026-05-04)

### Added
- **Inbound Message Coalescing Infrastructure (Single-Flight)**: Foundational code to prevent multiple parallel Reply-Cycles when users send related messages (text + file) as separate webhooks.
  - Per-sender state tracking with 3-second coalesce window (`COALESCE_WINDOW_MS`).
  - Automatic flush at 5 parts or window expiry (`COALESCE_MAX_PARTS`).
  - Part merging logic: combines text+file into single inbound context.
  - Queue support for parts arriving during in-flight dispatch.
  - Integration points ready in text handler (~line 2352) and file handler (~line 2576).

### Status
- Coalescing infrastructure complete and TypeScript-compiled.
- Integration into dispatch handlers deferred to main agent (pragmatic approach to minimize refactoring risk).
- All integration points documented in `/workspace/scout-reports/threema-coalescing-v0.6.7.md`.

## 0.6.6 (2026-05-04)

### Added
- **Idempotency Cache for Webhook Replay Protection**: Implements replay-attack protection against Threema webhook retries.
  - New message-ID deduplication mechanism with configurable TTL (24h) and cache size (500 entries max).
  - Automatic pruning of expired entries during check.
  - Disk persistence via `~/.openclaw/extensions/threema/.idempotency-cache/messageids.json` to survive plugin reloads.
  - Throttled writes (max 1 per 5 seconds) to prevent excessive I/O.
  - Prevents duplicate processing when Threema Gateway retries a failed webhook delivery.
  - Solves the issue where Plugin reloads during `npm publish` + temporary 5xx errors could cause the same message to be processed twice.

## 0.6.5 (2026-05-04)

### Added
- **Voice-Reply Function**: Threema plugin now supports sending voice notes (audio messages).
  - New `sendVoiceNote(toId, audioBuffer, mimeType, caption)` method on ThreemaClient for E2E encrypted voice messages.
  - When agent reply contains `audioAsVoice: true` with a `mediaUrl` (e.g., TTS or Whisper output), the plugin automatically sends it as a voice message instead of text.
  - Audio detection works in both text-inbound and file-inbound reply pipelines.
  - Fallback to text mode when audio file not found or when E2E mode is disabled (voice notes require E2E).
  - Supports multiple audio MIME types: audio/aac, audio/mpeg, audio/wav, audio/ogg, audio/m4a, audio/webm.
  - Error handling: logs errors and gracefully falls back to text delivery if voice send fails.

## 0.6.4 (2026-05-04)

### Fixed
- v0.6.3 introduced a regression where file inbounds always fell back to
  the legacy `enqueueSystemEvent` path. The new pipeline branch was
  trying to call a non-existent `channelRuntime.reply.resolveDirectSession-
  Key`. The text path doesn't use that helper at all; it uses
  `channelRuntime.routing.resolveAgentRoute` + `buildAgentSessionKey`.
  This release applies the same approach to the file path, so file
  inbounds finally land in the live Threema DM session.
- Symptom: `Threema file inbound pipeline error: channelRuntime.reply.
  resolveDirectSessionKey is not a function` followed by
  `dispatched via enqueueSystemEvent (fallback)` for every file message.

## 0.6.3 (2026-05-04)

### Fixed
- **File messages now route through the Channel Inbound Pipeline** like text
  messages, so they appear as part of the same Threema DM conversation
  the agent is already in. Previously file inbounds were dispatched via
  legacy `enqueueSystemEvent` against `agent:main:main`, which left them
  invisible to the running DM session: the agent only learned about the
  file by chance (e.g. by greping the inbound media folder later).
  Symptom hit on 2026-05-04 when the user shipped the OpenClaw
  2026.5.3 update protocol as a `.txt` file and the agent did not see it
  for ~20 minutes.

### Added
- File inbounds now expose `MediaPath` / `MediaType` / `MediaUrl` to the
  agent context (matching the convention used by the Matrix channel
  plugin). The agent can read the saved file directly with its normal
  tools (read / pdf / image) and reply in the same DM thread.
- The memory briefing block is now also injected into file inbounds, so
  the agent's acute-state context applies regardless of whether the
  user sent text or a file.
- Voice notes (audio file messages) get the same treatment: the
  Whisper transcription is included in the body, the audio path in
  `MediaPath`.

### Compatibility
- Falls back to the legacy `enqueueSystemEvent` path on older OpenClaw
  runtimes that don't expose `channelRuntime.reply.finalizeInboundContext`,
  or whenever the new pipeline path throws.

## 0.6.2 (2026-05-04)

### Fixed
- **Compiled runtime output** for the OpenClaw 2026.5.x npm-first plugin loader.
  The package now ships `dist/index.js` and points `main`/`exports`/
  `openclaw.extensions` at the compiled output. Previous releases shipped
  the raw `index.ts` only, which OpenClaw 2026.5.0+ rejects with:
  *"installed plugin package requires compiled runtime output for
  TypeScript entry index.ts"*.
- Added `tsconfig.json`, a `build`/`prepublishOnly` script, and `.npmignore`
  so future releases always include `dist/` and exclude `node_modules`.
- Cleaned a couple of strict-mode TypeScript signal-noise issues so the
  package builds cleanly with `@types/node@22` on Node 22.

### Added
- **`channelConfigs.threema` metadata** in `openclaw.plugin.json`. The
  2026.5.x setup surfaces and config schema engine read this; without it,
  doctor logs:
  *"channel plugin manifest declares threema without channelConfigs
  metadata"*. The previous flat `configSchema` is preserved for older
  OpenClaw versions.
- `build.openclawVersion` bumped to `2026.5.3`.

## 0.6.1 (2026-05-04)

### Added
- **Memory briefing hook** for inbound text messages. The plugin now appends an
  untrusted "memory_briefing" block to `BodyForAgent` on every inbound Threema
  text message. The block is composed at inbound time from two workspace files:
  - `MEMORY.md` -> the leading `## 📌 Current State` section
  - `memory/pending-actions.md` -> the leading `## 🔥 Akut` section
  Both reads are bounded (≤ 8 KB per file) and cached for 60 s.

  This makes long-running sessions resilient to staleness: even after weeks of
  conversation, the agent sees the user's current acute state on every reply
  without depending on memory recall heuristics. `RawBody`/`CommandBody` are
  unchanged, so slash-command routing is unaffected.

  Set the workspace via `agents.<id>.workspace` in the OpenClaw config; the
  plugin falls back to `~/.openclaw/workspace` when no agent declares one.

### Notes
- Backwards compatible: when neither file exists or both sections are missing,
  no briefing block is appended and `BodyForAgent` matches the original text.
- The briefing block uses the same untrusted-context conventions as other
  OpenClaw inbound metadata - it is informational, not instructions.

## 0.6.0

- Channel Inbound Pipeline integration.
- Slash command parsing.
- Long message chunking.
