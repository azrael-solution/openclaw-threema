# Changelog

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
