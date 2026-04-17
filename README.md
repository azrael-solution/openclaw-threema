# openclaw-threema

Threema Gateway channel plugin for [OpenClaw](https://github.com/openclaw/openclaw) — privacy-focused E2E encrypted messaging via the [Threema Gateway API](https://gateway.threema.ch/).

## Features

- **End-to-end encrypted** text messaging (NaCl box)
- **Media send/receive** — images, files, audio (E2E encrypted blobs)
- **Voice transcription** — automatic speech-to-text via local Whisper
- **Instant wake** — webhook-based message delivery (no polling)
- **Slash commands** — `/status`, `/compact`, etc. work natively via Threema (v0.6.0+)
- **CLI tools** — `openclaw threema send|send-file|status|keygen`

## Requirements

- A [Threema Gateway](https://gateway.threema.ch/) account (E2E mode)
- OpenClaw 2026.3.2+ with channel plugin support
- For voice transcription: [OpenAI Whisper](https://github.com/openai/whisper) installed locally

> **Note:** Threema Gateway usage is not free. At the time of writing, you need ~1,600 credits to register a Gateway ID, and each message costs 1 credit (~€0.02). 2,500 credits cost approximately €55.

## Installation

```bash
# From npm
npm install openclaw-threema

# From ClawHub
openclaw plugins install clawhub:threema

# Or as a local extension
cp -r . ~/.openclaw/extensions/threema/
cd ~/.openclaw/extensions/threema && npm install
```

Then add to your `openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "threema": {
        "enabled": true,
        "source": "~/.openclaw/extensions/threema/index.ts"
      }
    }
  },
  "channels": {
    "threema": {
      "enabled": true,
      "gatewayId": "*YOUR_ID",
      "secretKey": "your-gateway-secret",
      "privateKey": "your-nacl-private-key-hex",
      "dmPolicy": "allowlist",
      "allowFrom": ["ABCD1234"]
    }
  }
}
```

## Setup

### 1. Generate a key pair

```bash
openclaw threema keygen
```

This outputs a NaCl key pair. Add the private key to your config and upload the public key to the [Threema Gateway admin panel](https://gateway.threema.ch/).

### 2. Configure webhook

Set your Threema Gateway webhook URL to:

```
https://your-host:18789/threema/webhook
```

The default port is `18789` (OpenClaw Gateway). The path matches `webhookPath` in your config (default: `/threema/webhook`).

**Note:** If you're behind a reverse proxy (Cloudflare Tunnel, nginx, etc.), adjust the URL accordingly. The plugin registers the endpoint at the configured `webhookPath`.

### 3. Restart OpenClaw

```bash
openclaw gateway restart
```

### 4. Test

```bash
openclaw threema status
openclaw threema send ABCD1234 "Hello from OpenClaw!"
```

## DM Policies

| Policy | Description |
|--------|-------------|
| `allowlist` | Only IDs in `allowFrom` array (default, recommended) |
| `open` | Accept from anyone |
| `disabled` | Reject all DMs |

## Voice Transcription

When a voice message is received, the plugin automatically transcribes it using local Whisper (no API key needed). The transcription is included in the message delivered to the agent.

Whisper must be installed and accessible in PATH (e.g., `pip install openai-whisper`).

## Message Types Supported

- **Text** (type 0x01) — bidirectional
- **File** (type 0x17) — bidirectional (images, audio, documents)
- **Delivery receipts** (type 0x80) — inbound only

## Security

- All messages are end-to-end encrypted using NaCl (Curve25519 + XSalsa20-Poly1305)
- File blobs are encrypted with random symmetric keys (XSalsa20-Poly1305 secretbox)
- Private keys never leave the host
- Webhook verification via HMAC-SHA256 (mandatory, verified before decryption)
- SSRF protection: redirect blocking, DNS rebinding checks, private IP filtering
- Secrets are redacted in all log output

## Changelog

### v0.6.0 (2026-04-17)
- **Channel Inbound Pipeline** — messages now go through OpenClaw's native channel pipeline instead of raw `enqueueSystemEvent`. This enables slash commands (`/status`, `/compact`, etc.) directly from Threema.
- **Graceful fallback** — automatically falls back to `enqueueSystemEvent` if the channel pipeline is unavailable (e.g., older OpenClaw versions).
- **Long message chunking** — replies exceeding 3,500 chars are split at newline boundaries.

### v0.5.2 (2026-03-30)
- OpenClaw 2026.3.2 compatibility fixes
- Health monitor improvements
- ClawHub publishing support (`compat.pluginApi`, `build.openclawVersion`)

### v0.4.5 (2026-02-17)
- Initial npm release
- Full E2E text + media support
- Voice transcription via Whisper
- Security hardening (SSRF protection, path restrictions, PII log reduction)

## License

MIT
