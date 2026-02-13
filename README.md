# @openclaw/threema

Threema Gateway channel plugin for [OpenClaw](https://github.com/openclaw/openclaw) — privacy-focused E2E encrypted messaging via the [Threema Gateway API](https://gateway.threema.ch/).

## Features

- **End-to-end encrypted** text messaging (NaCl box)
- **Media send/receive** — images, files, audio (E2E encrypted blobs)
- **Voice transcription** — automatic speech-to-text via local Whisper
- **Instant wake** — webhook-based message delivery (no polling)
- **CLI tools** — `openclaw threema send|send-file|status|keygen`

## Requirements

- A [Threema Gateway](https://gateway.threema.ch/) account (E2E mode)
- OpenClaw v0.30+ with channel plugin support
- For voice transcription: [OpenAI Whisper](https://github.com/openai/whisper) installed locally

Please keep in mind that the use of the Threema Gateway is not for free.
At the time of writing these lines you have to pay 1.600 "Credits" to get an ID. 
Every Message costs another Credit (roughly EUR 0,02).
2.500 Credits are about EUR 55,00

## Installation

```bash
# From npm (when published)
npm install @openclaw/threema

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

**Note:** If you're behind a reverse proxy, adjust the URL accordingly. The plugin registers the endpoint at the configured `webhookPath`.

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
| `allowlist` | Only IDs in `allowFrom` array (default) |
| `open` | Accept from anyone |
| `disabled` | Reject all DMs |

## Voice Transcription

When a voice message is received, the plugin automatically transcribes it using local Whisper (no API key needed). The transcription is included in the message delivered to the agent.

Whisper must be installed and accessible in PATH (e.g., via `pip install openai-whisper` or Homebrew).

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

## License

MIT

