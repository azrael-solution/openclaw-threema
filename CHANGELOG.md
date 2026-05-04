# Changelog

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
