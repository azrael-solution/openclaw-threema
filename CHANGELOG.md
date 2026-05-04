# Changelog

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
