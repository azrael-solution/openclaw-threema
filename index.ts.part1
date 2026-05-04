/**
 * Threema Gateway Plugin for OpenClaw
 *
 * Implements a proper channel plugin following the OpenClaw SDK interface.
 * Supports E2E encrypted messaging via Threema Gateway API.
 * Includes media (file message) support with audio transcription.
 */

import nacl from "tweetnacl";
import { decodeUTF8 } from "tweetnacl-util";
import * as fs from "fs";
import * as path from "path";
import { spawnSync } from "child_process";
import * as crypto from "crypto";
import * as dns from "node:dns/promises";

// ============================================================================
// Types (matching OpenClaw's expected interfaces)
// ============================================================================

interface ThreemaConfig {
  enabled?: boolean;
  gatewayId: string;
  secretKey: string;
  privateKey?: string; // hex-encoded NaCl private key for E2E
  webhookPath?: string;
  dmPolicy?: "pairing" | "allowlist" | "open" | "disabled";
  allowFrom?: string[];
  textChunkLimit?: number;
}

interface ResolvedThreemaAccount extends ThreemaConfig {
  accountId: string;
}

// OpenClaw SDK types (simplified for this plugin)
interface OpenClawConfig {
  channels?: {
    threema?: ThreemaConfig;
  };
  plugins?: {
    entries?: {
      threema?: {
        config?: ThreemaConfig;
      };
    };
  };
  gateway?: {
    port?: number;
    auth?: {
      token?: string;
    };
  };
}

interface ChannelOutboundContext {
  cfg: OpenClawConfig;
  to: string;
  text: string;
  mediaUrl?: string;
  gifPlayback?: boolean;
  replyToId?: string | null;
  threadId?: string | number | null;
  accountId?: string | null;
  deps?: unknown;
}

interface OutboundDeliveryResult {
  channel: string;
  messageId: string;
  chatId?: string;
  timestamp?: number;
}

interface ChannelGatewayContext {
  cfg: OpenClawConfig;
  accountId: string;
  account: ResolvedThreemaAccount;
  runtime: RuntimeEnv;
  abortSignal: AbortSignal;
  log?: ChannelLogSink;
  getStatus: () => ChannelAccountSnapshot;
  setStatus: (next: ChannelAccountSnapshot) => void;
}

interface ChannelAccountSnapshot {
  accountId: string;
  name?: string;
  enabled?: boolean;
  configured?: boolean;
  linked?: boolean;
  running?: boolean;
  connected?: boolean;
  lastConnectedAt?: number | null;
  lastError?: string | null;
  webhookPath?: string;
}

interface ChannelLogSink {
  info: (msg: string) => void;
  warn: (msg: string) => void;
  error: (msg: string) => void;
  debug?: (msg: string) => void;
}

interface RuntimeEnv {
  stateDir?: string;
}

interface MsgContext {
  Body?: string;
  BodyForAgent?: string;
  CommandBody?: string;
  From?: string;
  To?: string;
  SessionKey?: string;
  AccountId?: string;
  MessageSid?: string;
  ChatType?: string;
}

// File message JSON structure (after decryption)
interface ThreemaFileMessage {
  b: string;  // blob ID (hex)
  k: string;  // encryption key (hex)
  m: string;  // MIME type
  n?: string; // filename
  s: number;  // size in bytes
  t?: string; // thumbnail blob ID (optional)
  p?: string; // thumbnail media type (optional, default image/jpeg)
  d?: string; // caption/description (optional)
  j?: number; // rendering type: 0=file, 1=media, 2=sticker
  i?: number; // deprecated rendering flag
  c?: string; // correlation ID
  x?: Record<string, unknown>; // metadata (dimensions, duration, etc.)
}

// ============================================================================
// Constants
// ============================================================================

const THREEMA_API_BASE = "https://msgapi.threema.ch";
const MEDIA_INBOUND_DIR = path.join(
  process.env.HOME || "/tmp",
  ".openclaw",
  "media",
  "inbound"
);

// ============================================================================
// Memory Briefing Hook
// ============================================================================
//
// Injects an up-to-date "acute state" snapshot from the workspace memory into
// every inbound Threema message that goes to the agent. This compensates for
// long-running sessions where MEMORY.md was loaded weeks ago and may not be
// salient for the current reply. Format mirrors OpenClaw's untrusted-context
// blocks so the agent treats it as informational, not as instructions.
//
// Sources read on each inbound (best-effort, fail-silent):
//   1. <workspace>/MEMORY.md  -> only the leading "\ud83d\udccc Current State" block
//   2. <workspace>/memory/pending-actions.md -> only the "\ud83d\udd25 Akut" section
//
// File reads are bounded (<= 8 KB each) and cached for 60 s to avoid disk
// thrash on bursts of messages.

interface BriefingCacheEntry {
  text: string;
  expiresAt: number;
}
const briefingCache: Map<string, BriefingCacheEntry> = new Map();
const BRIEFING_CACHE_TTL_MS = 60_000;
const BRIEFING_MAX_BYTES = 8192;

function readBoundedFile(filePath: string): string {
  try {
    const stat = fs.statSync(filePath);
    if (!stat.isFile()) return "";
    const fd = fs.openSync(filePath, "r");
    try {
      const len = Math.min(stat.size, BRIEFING_MAX_BYTES);
      const buf = Buffer.alloc(len);
      fs.readSync(fd, buf, 0, len, 0);
      return buf.toString("utf8");
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return "";
  }
}

function extractCurrentStateBlock(memoryMd: string): string {
  if (!memoryMd) return "";
  // Find the line starting with "## \ud83d\udccc Current State" (or any "## *Current State*")
  const lines = memoryMd.split(/\r?\n/);
  let startIdx = -1;
  for (let i = 0; i < lines.length; i++) {
    if (/^##\s.*Current State/i.test(lines[i])) {
      startIdx = i;
      break;
    }
  }
  if (startIdx < 0) return "";
  // Read until the next "## " header
  const out: string[] = [];
  for (let i = startIdx; i < lines.length; i++) {
    if (i > startIdx && /^##\s/.test(lines[i])) break;
    out.push(lines[i]);
  }
  return out.join("\n").trim();
}

function extractAcutePending(pendingMd: string): string {
  if (!pendingMd) return "";
  const lines = pendingMd.split(/\r?\n/);
  let startIdx = -1;
  for (let i = 0; i < lines.length; i++) {
    if (/^##\s.*Akut/i.test(lines[i])) {
      startIdx = i;
      break;
    }
  }
  if (startIdx < 0) return "";
  const out: string[] = [];
  for (let i = startIdx; i < lines.length; i++) {
    if (i > startIdx && /^##\s/.test(lines[i])) break;
    out.push(lines[i]);
  }
  return out.join("\n").trim();
}

function resolveWorkspaceDir(cfg: OpenClawConfig | undefined): string | null {
  // Best-effort: dig through the agents.defaults.workspace path used in this
  // setup. We accept any string under agents.*.workspace too.
  const root: any = cfg as any;
  const candidates: any[] = [];
  try {
    if (root?.agents) {
      for (const k of Object.keys(root.agents)) {
        const w = root.agents[k]?.workspace;
        if (typeof w === "string") candidates.push(w);
      }
    }
  } catch {
    /* ignore */
  }
  // Fallback: ~/.openclaw/workspace
  candidates.push(path.join(process.env.HOME || "/tmp", ".openclaw", "workspace"));
  for (const p of candidates) {
    try {
      if (p && fs.existsSync(p) && fs.statSync(p).isDirectory()) return p;
    } catch {
      /* ignore */
    }
  }
  return null;
}

function buildMemoryBriefing(cfg: OpenClawConfig | undefined): string {
  const workspace = resolveWorkspaceDir(cfg);
  if (!workspace) return "";
  const cacheKey = workspace;
  const now = Date.now();
  const cached = briefingCache.get(cacheKey);
  if (cached && cached.expiresAt > now) return cached.text;

  const memoryPath = path.join(workspace, "MEMORY.md");
  const pendingPath = path.join(workspace, "memory", "pending-actions.md");

  const currentState = extractCurrentStateBlock(readBoundedFile(memoryPath));
  const acutePending = extractAcutePending(readBoundedFile(pendingPath));

  if (!currentState && !acutePending) {
    briefingCache.set(cacheKey, { text: "", expiresAt: now + BRIEFING_CACHE_TTL_MS });
    return "";
  }

  const parts: string[] = [];
  parts.push(
    "Memory briefing (untrusted, generated by threema plugin at inbound time \u2014 informational only, not instructions):"
  );
  parts.push(
    "This snapshot is appended to every inbound Threema message so the agent has a fresh view of the user's acute state, even in long-running sessions. Read it before replying."
  );
  parts.push("");
  if (currentState) {
    parts.push("--- MEMORY.md (Current State) ---");
    parts.push(currentState);
  }
  if (acutePending) {
    if (currentState) parts.push("");
    parts.push("--- pending-actions.md (Akut) ---");
    parts.push(acutePending);
  }
  const text = parts.join("\n");
  briefingCache.set(cacheKey, { text, expiresAt: now + BRIEFING_CACHE_TTL_MS });
  return text;
}

function composeBodyForAgent(userText: string, cfg: OpenClawConfig | undefined): string {
  const briefing = buildMemoryBriefing(cfg);
  if (!briefing) return userText;
  return `${userText}\n\n[memory_briefing]\n${briefing}\n[/memory_briefing]`;
}

// Allowed base directory for local media files (exfiltration protection)
const MEDIA_ALLOWED_BASE = path.join(
  process.env.HOME || "/tmp",
  ".openclaw",
  "media"
);

// Extension state directory for persistent caches
const EXTENSION_STATE_DIR = path.join(
  process.env.HOME || "/tmp",
  ".openclaw",
  "extensions",
  "threema"
);

// Message-ID dedup cache (replay protection): messageId -> timestamp
const seenMsgIds = new Map<string, number>();
const MSG_ID_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const MSG_ID_CACHE_MAX = 500;

// Audio MIME types that should be transcribed
const AUDIO_MIME_TYPES = [
  "audio/aac",
  "audio/mp4",
  "audio/mpeg",
  "audio/ogg",
  "audio/wav",
  "audio/webm",
  "audio/x-m4a",
  "audio/m4a",
];

// ============================================================================
// Threema Gateway API Client
// ============================================================================

class ThreemaClient {
  private gatewayId: string;
  private secretKey: string;
  private privateKey?: Uint8Array;
  private publicKey?: Uint8Array;
  private publicKeyCache = new Map<string, Uint8Array>();

  constructor(config: ThreemaConfig) {
    this.gatewayId = config.gatewayId;
    this.secretKey = config.secretKey;

    if (config.privateKey) {
      this.privateKey = hexToBytes(config.privateKey);
      const keyPair = nacl.box.keyPair.fromSecretKey(this.privateKey);
      this.publicKey = keyPair.publicKey;
    }
  }

  /**
   * Send a text message (E2E mode - client-side encryption)
   */
  async sendE2E(to: string, text: string): Promise<string> {
    if (!this.privateKey) {
      throw new Error("E2E mode requires privateKey configuration");
    }

    const recipientPubKey = await this.getPublicKey(to);

    // Create message payload (type 0x01 = text) with spec-compliant random padding
    const textBytes = decodeUTF8(text);
    const payload = buildE2EPayload(0x01, textBytes);

    // Generate nonce and encrypt
    const nonce = nacl.randomBytes(24);
    const box = nacl.box(payload, nonce, recipientPubKey, this.privateKey);

    const params = new URLSearchParams({
      from: this.gatewayId,
      to,
      nonce: bytesToHex(nonce),
      box: bytesToHex(box),
      secret: this.secretKey,
    });

    const url = `${THREEMA_API_BASE}/send_e2e`;
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString(),
    });

    if (!res.ok) {
      // Don't log response body (may contain secrets)
      throw new Error(`Threema E2E API error ${res.status}`);
    }

    return res.text();
  }

  /**
   * Send a file message (E2E mode)
   */
  async sendFileE2E(
    to: string,
    filePath: string,
    mimeType: string,
    caption?: string
  ): Promise<string> {
    if (!this.privateKey) {
      throw new Error("E2E mode requires privateKey configuration");
    }

    const recipientPubKey = await this.getPublicKey(to);

    // Read the file
    const fileData = fs.readFileSync(filePath);
    const fileName = path.basename(filePath);
    const fileSize = fileData.length;

    // Generate random symmetric key for file encryption
    const fileKey = nacl.randomBytes(32);
    // Threema FILE_NONCE: 23 zero bytes + 0x01
    const fileNonce = new Uint8Array(24);
    fileNonce[23] = 0x01;

    // Encrypt the file with secretbox
    const encryptedFile = nacl.secretbox(new Uint8Array(fileData), fileNonce, fileKey);

    // Upload encrypted blob
    const blobId = await this.uploadBlob(encryptedFile);

    // Create file message JSON
    const isMedia = /^(image|video|audio)\//i.test(mimeType);
    const fileMsg: ThreemaFileMessage = {
      b: blobId,
      k: bytesToHex(fileKey),
      m: mimeType,
      n: fileName,
      s: fileSize,
      j: isMedia ? 1 : 0,  // 1 = render as media, 0 = render as file
      i: isMedia ? 1 : 0,  // deprecated but needed for older clients
    };
    if (caption) {
      fileMsg.d = caption;
    }

    const fileMsgJson = JSON.stringify(fileMsg);
    const fileMsgBytes = decodeUTF8(fileMsgJson);

    // Create E2E payload (type 0x17 = file message) with spec-compliant random padding
    const payload = buildE2EPayload(0x17, fileMsgBytes);

    // Generate nonce and encrypt with NaCl box
    const nonce = nacl.randomBytes(24);
    const box = nacl.box(payload, nonce, recipientPubKey, this.privateKey);

    const params = new URLSearchParams({
      from: this.gatewayId,
      to,
      nonce: bytesToHex(nonce),
      box: bytesToHex(box),
      secret: this.secretKey,
    });

    const url = `${THREEMA_API_BASE}/send_e2e`;
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString(),
    });

    if (!res.ok) {
      // Don't log response body (may contain secrets)
      throw new Error(`Threema E2E API error ${res.status}`);
    }

    return res.text();
  }

  /**
   * Upload an encrypted blob to Threema servers
   */
  async uploadBlob(encryptedData: Uint8Array): Promise<string> {
    const formData = new FormData();
    // Cast to ArrayBuffer to satisfy strict TS DOM types (Uint8Array<ArrayBufferLike> vs ArrayBufferView<ArrayBuffer>)
    formData.append("blob", new Blob([encryptedData as unknown as BlobPart]), "blob");

    const url = `${THREEMA_API_BASE}/upload_blob?from=${this.gatewayId}&secret=${this.secretKey}`;

    const res = await fetch(url, {
      method: "POST",
      body: formData,
    });

    if (!res.ok) {
      // Don't log response body or URL (contains secret)
      throw new Error(`Threema blob upload error ${res.status}: ${sanitizeUrl(url)}`);
    }

    // Response is the blob ID
    return (await res.text()).trim();
  }

  /**
   * Download an encrypted blob from Threema servers
   */
  async downloadBlob(blobId: string): Promise<Uint8Array> {
    const url = `${THREEMA_API_BASE}/blobs/${blobId}?from=${this.gatewayId}&secret=${this.secretKey}`;

    const res = await fetch(url);

    if (!res.ok) {
      // Don't log response body or full URL (contains secret)
      throw new Error(`Threema blob download error ${res.status}: ${sanitizeUrl(url)}`);
    }

    const buffer = await res.arrayBuffer();
    return new Uint8Array(buffer);
  }

  /**
   * Decrypt a file blob using secretbox
   */
  decryptBlob(encryptedBlob: Uint8Array, keyHex: string, isThumbnail = false): Uint8Array | null {
    const key = hexToBytes(keyHex);
    // Threema uses specific nonces: 23 zero bytes + 0x01 for files, 0x02 for thumbnails
    const nonce = new Uint8Array(24);
    nonce[23] = isThumbnail ? 0x02 : 0x01;

    const decrypted = nacl.secretbox.open(encryptedBlob, nonce, key);
    return decrypted || null;
  }

  /**
   * Send a voice note message (audio file with voice message rendering type).
   * Type 0x17 file message with j=1 (media rendering) and audio MIME type.
   * Suitable for Whisper transcriptions or agent-generated TTS audio.
   */
  async sendVoiceNote(
    to: string,
    audioBuffer: Buffer,
    mimeType: string = "audio/aac",
    caption?: string
  ): Promise<string> {
    if (!this.privateKey) {
      throw new Error("E2E mode requires privateKey configuration");
    }

    const recipientPubKey = await this.getPublicKey(to);

    // Generate random symmetric key for file encryption
    const fileKey = nacl.randomBytes(32);
    // Threema FILE_NONCE: 23 zero bytes + 0x01
    const fileNonce = new Uint8Array(24);
    fileNonce[23] = 0x01;

    // Encrypt the audio with secretbox
    const encryptedAudio = nacl.secretbox(new Uint8Array(audioBuffer), fileNonce, fileKey);

    // Upload encrypted blob
    const blobId = await this.uploadBlob(encryptedAudio);

    // Create file message JSON for voice note
    // j=1 marks it as media (voice message bubble in UI)
    const fileMsg: ThreemaFileMessage = {
      b: blobId,
      k: bytesToHex(fileKey),
      m: mimeType,
      n: `voice.${this.getMimeExtension(mimeType)}`,
      s: audioBuffer.length,
      j: 1,  // 1 = render as media (voice message bubble)
      i: 1,  // deprecated but needed for older clients
    };
    if (caption) {
      fileMsg.d = caption;
    }

    const fileMsgJson = JSON.stringify(fileMsg);
    const fileMsgBytes = decodeUTF8(fileMsgJson);

    // Create E2E payload (type 0x17 = file message)
    const payload = buildE2EPayload(0x17, fileMsgBytes);

    // Generate nonce and encrypt with NaCl box
    const nonce = nacl.randomBytes(24);
    const box = nacl.box(payload, nonce, recipientPubKey, this.privateKey);

    const params = new URLSearchParams({
      from: this.gatewayId,
      to,
      nonce: bytesToHex(nonce),
      box: bytesToHex(box),
      secret: this.secretKey,
    });

    const url = `${THREEMA_API_BASE}/send_e2e`;
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString(),
    });

    if (!res.ok) {
      // Don't log response body (may contain secrets)
      throw new Error(`Threema E2E API error ${res.status}`);
    }

    return res.text();
  }

  /**
   * Get file extension for MIME type
   */
  private getMimeExtension(mimeType: string): string {
    const mimeMap: Record<string, string> = {
      "audio/aac": "aac",
      "audio/mpeg": "mp3",
      "audio/wav": "wav",
      "audio/ogg": "ogg",
      "audio/m4a": "m4a",
      "audio/webm": "webm",
    };
    return mimeMap[mimeType.toLowerCase()] || "m4a";
  }

  /**
   * Send a text message (Basic mode - server-side encryption)
   */
  async sendSimple(to: string, text: string): Promise<string> {
    const params = new URLSearchParams({
      from: this.gatewayId,
      to,
      text,
      secret: this.secretKey,
    });

    const url = `${THREEMA_API_BASE}/send_simple`;
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString(),
    });

    if (!res.ok) {
      // Don't log response body (may contain secrets)
      throw new Error(`Threema API error ${res.status}`);
    }

    return res.text();
  }

  /**
   * Get public key for a Threema ID
   */
  async getPublicKey(threemaId: string): Promise<Uint8Array> {
    const cached = this.publicKeyCache.get(threemaId);
    if (cached) return cached;

    const url = `${THREEMA_API_BASE}/pubkeys/${threemaId}?from=${this.gatewayId}&secret=${this.secretKey}`;
    const res = await fetch(url);

    if (!res.ok) {
      // Don't include URL in error (contains secret)
      throw new Error(
        `Failed to get public key for ${threemaId}: ${res.status}`
      );
    }

    const hexKey = await res.text();
    const pubKey = hexToBytes(hexKey);
    this.publicKeyCache.set(threemaId, pubKey);
    return pubKey;
  }

  /**
   * Decrypt an incoming E2E message
   */
  decryptMessage(
    senderPubKey: Uint8Array,
    nonce: Uint8Array,
    box: Uint8Array
  ):
    | {
        type: number;
        text?: string;
        status?: number;
        messageIds?: string[];
        fileMessage?: ThreemaFileMessage;
      }
    | null {
    if (!this.privateKey) return null;

    const decrypted = nacl.box.open(box, nonce, senderPubKey, this.privateKey);
    if (!decrypted) return null;

    // Validate PKCS7 padding
    const padLen = decrypted[decrypted.length - 1];
    
    // padLen must be 1-255
    if (padLen < 1) return null;
    
    // decrypted.length must be at least 1 (type) + padLen
    if (decrypted.length < 1 + padLen) return null;
    
    // PKCS7 consistency: all last padLen bytes must equal padLen
    for (let i = decrypted.length - padLen; i < decrypted.length; i++) {
      if (decrypted[i] !== padLen) return null;
    }

    const type = decrypted[0];

    // Remove PKCS7 padding
    const unpaddedLen = decrypted.length - padLen;
    const payload = decrypted.slice(1, unpaddedLen);

    if (type === 0x01) {
      // Text message
      const text = new TextDecoder("utf-8").decode(payload);
      return { type, text };
    }

    if (type === 0x17) {
      // File message - payload is JSON
      const jsonStr = new TextDecoder("utf-8").decode(payload);
      try {
        const fileMessage = JSON.parse(jsonStr) as ThreemaFileMessage;
        return { type, fileMessage };
      } catch (e: any) {
        // Log parse failure (no raw data to avoid leaking message content)
        // File JSON parse error is logged at processing level
        return { type };
      }
    }

    if (type === 0x80) {
      // Delivery receipt
      const status = payload[0];
      const messageIds: string[] = [];
      for (let i = 1; i < payload.length; i += 8) {
        const idBytes = payload.slice(i, i + 8);
        messageIds.push(bytesToHex(idBytes));
      }
      return { type, status, messageIds };
    }

    // Other message types (image 0x02, video 0x13, audio 0x14, location 0x10)
    return { type };
  }

  get isE2EEnabled(): boolean {
    return !!this.privateKey;
  }

  get ownPublicKey(): string | undefined {
    return this.publicKey ? bytesToHex(this.publicKey) : undefined;
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function generateKeyPair(): { privateKey: string; publicKey: string } {
  const keyPair = nacl.box.keyPair();
  return {
    privateKey: bytesToHex(keyPair.secretKey),
    publicKey: bytesToHex(keyPair.publicKey),
  };
}

/**
 * Build E2E payload with spec-compliant PKCS7 random padding
 * Random padding 1-255 bytes, minimum 32 bytes padded-data (EXCLUDING type byte per Threema spec)
 */
function buildE2EPayload(type: number, inner: Uint8Array): Uint8Array {
  const MIN_PADDED_DATA_SIZE = 32; // inner + padding >= 32 (excluding type byte)
  
  // Random pad length 1-255 bytes
  const randByte = nacl.randomBytes(1)[0];
  let padLen = (randByte % 255) + 1; // 1-255
  
  // Ensure inner + padLen >= 32 (padded-data without type byte)
  if (inner.length + padLen < MIN_PADDED_DATA_SIZE) {
    padLen = MIN_PADDED_DATA_SIZE - inner.length;
  }
  
  // payload = 1 (type) + inner.length + padLen
  const payload = new Uint8Array(1 + inner.length + padLen);
  payload[0] = type;
  payload.set(inner, 1);
  
  // Fill with PKCS7 padding (pad byte = padding length)
  const padByte = padLen & 0xff;
  for (let i = 1 + inner.length; i < payload.length; i++) {
    payload[i] = padByte;
  }
  
  return payload;
}

/**
 * Check if a message ID has been seen recently (replay protection)
 * Returns true if duplicate (should be ignored)
 */
// Idempotency cache directory
const CACHE_DIR = path.join(EXTENSION_STATE_DIR, ".idempotency-cache");
const CACHE_FILE = path.join(CACHE_DIR, "messageids.json");
let lastCacheSave = 0;
const CACHE_SAVE_THROTTLE_MS = 5000; // Max 1 write per 5 sec

/**
 * Load idempotency cache from disk if available and fresh
 */
function loadIdempotencyCache(): void {
  try {
    if (!fs.existsSync(CACHE_FILE)) return;
    
    const data = fs.readFileSync(CACHE_FILE, "utf-8");
    const parsed = JSON.parse(data);
    if (!parsed || typeof parsed !== "object") return;
    
    const now = Date.now();
    for (const [id, ts] of Object.entries(parsed)) {
      const timestamp = Number(ts);
      // Only load entries that are still within TTL
      if (!isNaN(timestamp) && now - timestamp < MSG_ID_TTL_MS) {
        seenMsgIds.set(id, timestamp);
      }
    }
  } catch (err: any) {
    // Silently skip if cache file is corrupted or unreadable
    // Next write will overwrite it
  }
}

/**
 * Save idempotency cache to disk (throttled)
 */
function saveIdempotencyCache(): void {
  const now = Date.now();
  if (now - lastCacheSave < CACHE_SAVE_THROTTLE_MS) {
    return; // Skip this write, within throttle window
  }
  lastCacheSave = now;
  
  try {
    if (!fs.existsSync(CACHE_DIR)) {
      fs.mkdirSync(CACHE_DIR, { recursive: true });
    }
    const obj: Record<string, number> = {};
    for (const [id, ts] of seenMsgIds) {
      obj[id] = ts;
    }
    fs.writeFileSync(CACHE_FILE, JSON.stringify(obj, null, 2), "utf-8");
  } catch (err: any) {
    // Silently skip if write fails; in-memory cache is still valid
  }
}

/**
 * Check if message has been seen before (idempotency check)
 * Returns true if duplicate (should skip), false if new (should process)
 */
function isDuplicateMsgId(messageId: string): boolean {
  const now = Date.now();
  
  // Prune entries older than TTL
  for (const [id, ts] of seenMsgIds) {
    if (now - ts > MSG_ID_TTL_MS) {
      seenMsgIds.delete(id);
    }
  }
  
  // If cache is still too large, evict oldest entries
  if (seenMsgIds.size >= MSG_ID_CACHE_MAX) {
    // Find and remove the oldest entry
    let oldest = messageId;
    let oldestTs = now;
    for (const [id, ts] of seenMsgIds) {
      if (ts < oldestTs) {
        oldest = id;
        oldestTs = ts;
      }
    }
    if (oldest !== messageId) {
      seenMsgIds.delete(oldest);
    }
  }
  
  // Check if seen
  const seenAt = seenMsgIds.get(messageId);
  if (seenAt && now - seenAt < MSG_ID_TTL_MS) {
    return true; // duplicate
  }
  
  // Mark as seen
  seenMsgIds.set(messageId, now);
  saveIdempotencyCache(); // Throttled write
  return false;
}

/**
 * Sanitize URL by redacting secret query parameter
 * Prevents API secrets from leaking into logs/error messages
 */
function sanitizeUrl(url: string): string {
  try {
    const parsed = new URL(url);
    if (parsed.searchParams.has("secret")) {
      parsed.searchParams.set("secret", "REDACTED");
    }
    return parsed.toString();
  } catch {
    // If URL parsing fails, do regex replacement
    return url.replace(/secret=[^&]+/gi, "secret=REDACTED");
  }
}

/**
 * Check if an IP address is private/internal (for SSRF protection)
 */
function isPrivateIP(ip: string): boolean {
  // Normalize IPv6-mapped IPv4 (::ffff:127.0.0.1 -> 127.0.0.1)
  const normalizedIP = ip.replace(/^::ffff:/i, "");
  
  // Check IPv4
  const ipv4Match = normalizedIP.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (ipv4Match) {
    const [, a, b, c] = ipv4Match.map(Number);
    // 0.0.0.0/8 (current network)
    if (a === 0) return true;
    // 10.0.0.0/8 (private)
    if (a === 10) return true;
    // 127.0.0.0/8 (loopback)
    if (a === 127) return true;
    // 169.254.0.0/16 (link-local)
    if (a === 169 && b === 254) return true;
    // 172.16.0.0/12 (private)
    if (a === 172 && b >= 16 && b <= 31) return true;
    // 192.168.0.0/16 (private)
    if (a === 192 && b === 168) return true;
    // 100.64.0.0/10 (CGNAT)
    if (a === 100 && b >= 64 && b <= 127) return true;
    return false;
  }
  
  // Check IPv6
  const ipLower = ip.toLowerCase();
  // ::1 (loopback)
  if (ipLower === "::1") return true;
  // fc00::/7 (unique local)
  if (ipLower.startsWith("fc") || ipLower.startsWith("fd")) return true;
  // fe80::/10 (link-local)
  if (ipLower.startsWith("fe8") || ipLower.startsWith("fe9") || 
      ipLower.startsWith("fea") || ipLower.startsWith("feb")) return true;
  
  return false;
}

/**
 * Resolve hostname via DNS and check if it resolves to a private IP (DNS rebinding protection)
 */
async function resolveAndCheckPrivate(hostname: string): Promise<{ isPrivate: boolean; resolvedIP?: string }> {
  // Block .local domains (mDNS)
  if (hostname.toLowerCase().endsWith(".local")) {
    return { isPrivate: true };
  }
  
  // Block localhost explicitly
  if (hostname.toLowerCase() === "localhost") {
    return { isPrivate: true, resolvedIP: "127.0.0.1" };
  }
  
  try {
    // Resolve hostname to ALL IPs (multi-A/AAAA protection)
    const results = await dns.lookup(hostname, { all: true });
    
    // Block if ANY resolved IP is private
    for (const result of results) {
      if (isPrivateIP(result.address)) {
        return { isPrivate: true, resolvedIP: result.address };
      }
    }
    
    return { isPrivate: false, resolvedIP: results[0]?.address };
  } catch {
    // DNS resolution failed - block to be safe
    return { isPrivate: true };
  }
}

/**
 * Check if URL hostname is a private/internal IP (SSRF protection)
 * Note: This only checks the hostname string, not resolved IP.
 * Use resolveAndCheckPrivate() for DNS rebinding protection.
 */
function isPrivateUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();
    
    // Block localhost and .local domains
    if (hostname === "localhost" || hostname.endsWith(".local")) {
      return true;
    }
    
    // Block IPv4/IPv6 loopback in URL
    if (hostname === "127.0.0.1" || hostname === "[::1]" || hostname === "::1") {
      return true;
    }
    
    // Block private IPv4 ranges when IP is directly in URL
    const ipv4Match = hostname.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if (ipv4Match) {
      return isPrivateIP(hostname);
    }
    
    // Block IPv6 private when IP is directly in URL
    if (hostname.startsWith("[fc") || hostname.startsWith("[fd") ||
        hostname.startsWith("[fe8") || hostname.startsWith("[fe9")) {
      return true;
    }
    
    return false;
  } catch {
    return true; // Invalid URL = block
  }
}

/**
 * Validate local file path is within allowed media directory
 * Prevents exfiltration of arbitrary files
 */
function validateLocalMediaPath(filePath: string): { valid: boolean; realPath?: string; error?: string } {
  try {
    // Resolve symlinks and normalize path
    const realPath = fs.realpathSync(filePath);
    
    // Ensure the allowed base exists (create if needed for the check)
    if (!fs.existsSync(MEDIA_ALLOWED_BASE)) {
      fs.mkdirSync(MEDIA_ALLOWED_BASE, { recursive: true, mode: 0o700 });
    }
    const allowedBase = fs.realpathSync(MEDIA_ALLOWED_BASE);
    
    // Check if real path is within allowed directory
    if (!realPath.startsWith(allowedBase + path.sep) && realPath !== allowedBase) {
      return { 
        valid: false, 
        error: "Local file path not allowed outside media directory" 
      };
    }
    
    return { valid: true, realPath };
  } catch (err: any) {
    if (err.code === "ENOENT") {
      return { valid: false, error: "File not found" };
    }
    return { valid: false, error: `Path validation failed: ${err.message}` };
  }
}

/**
 * Sanitize filename: only allow safe characters
 */
function sanitizeFilename(filename: string): string {
  // Only allow alphanumeric, dots, dashes, and underscores
  const sanitized = filename.replace(/[^a-zA-Z0-9._-]/g, "_");
  // Prevent directory traversal and hidden files
  return sanitized.replace(/^\.+/, "_").replace(/\.{2,}/g, "_");
}

/**
 * Compute Threema callback MAC for webhook verification
 * MAC = HMAC-SHA256(from || to || messageId || date || nonce || box, secret)
 */
function computeThreemaCallbackMac(
  from: string,
  to: string,
  messageId: string,
  date: string,
  nonce: string,
  box: string,
  secret: string
): string {
  const data = from + to + messageId + date + nonce + box;
  return crypto.createHmac("sha256", secret).update(data).digest("hex");
}

/**
 * Constant-time comparison for MAC verification
 */
function verifyMac(received: string, computed: string): boolean {
  if (received.length !== computed.length) return false;
  try {
    const a = Buffer.from(received, "hex");
    const b = Buffer.from(computed, "hex");
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

/**
 * Validate Threema webhook field formats
 */
function validateWebhookFields(body: any): { valid: boolean; error?: string } {
  const { from, to, messageId, nonce, box, mac, date } = body;
  
  // from/to: 8 characters
  if (!from || typeof from !== "string" || !/^[A-Z0-9*]{8}$/.test(from)) {
    return { valid: false, error: "Invalid 'from' format" };
  }
  if (!to || typeof to !== "string" || !/^[A-Z0-9*]{8}$/.test(to)) {
    return { valid: false, error: "Invalid 'to' format" };
  }
  
  // messageId: 16 hex chars
  if (!messageId || typeof messageId !== "string" || !/^[a-fA-F0-9]{16}$/.test(messageId)) {
    return { valid: false, error: "Invalid 'messageId' format" };
  }
  
  // nonce: 48 hex chars (24 bytes)
  if (!nonce || typeof nonce !== "string" || !/^[a-fA-F0-9]{48}$/.test(nonce)) {
    return { valid: false, error: "Invalid 'nonce' format" };
  }
  
  // mac: 64 hex chars (32 bytes)
  if (!mac || typeof mac !== "string" || !/^[a-fA-F0-9]{64}$/.test(mac)) {
    return { valid: false, error: "Invalid 'mac' format" };
  }
  
  // box: non-empty hex
  if (!box || typeof box !== "string" || !/^[a-fA-F0-9]+$/.test(box)) {
    return { valid: false, error: "Invalid 'box' format" };
  }
  
  // date: numeric string (Unix timestamp)
  if (date !== undefined && (typeof date !== "string" || !/^\d+$/.test(date))) {
    return { valid: false, error: "Invalid 'date' format" };
  }
  
  return { valid: true };
}

/**
 * Read request body with size limit
 */
async function readBodyLimited(req: any, maxBytes: number = 128 * 1024): Promise<any> {
  return new Promise((resolve, reject) => {
    let data = "";
    let received = 0;
    
    const onData = (chunk: Buffer | string) => {
      const chunkLen = Buffer.byteLength(chunk);
      received += chunkLen;
      
      if (received > maxBytes) {
        req.removeListener("data", onData);
        req.destroy();
        reject(new Error("BODY_TOO_LARGE"));
        return;
      }
      
      data += chunk;
    };
    
    req.on("data", onData);
    req.on("end", () => {
      try {
        if (req.headers["content-type"]?.includes("json")) {
          resolve(JSON.parse(data));
        } else {
          const params = new URLSearchParams(data);
          resolve(Object.fromEntries(params));
        }
      } catch (e) {
        reject(e);
      }
    });
    req.on("error", reject);
  });
}

function chunkText(text: string, limit: number): string[] {
  if (text.length <= limit) return [text];

  const chunks: string[] = [];
  let remaining = text;

  while (remaining.length > 0) {
    if (remaining.length <= limit) {
      chunks.push(remaining);
      break;
    }

    // Try to break at newline or space
    let breakPoint = remaining.lastIndexOf("\n", limit);
    if (breakPoint < limit * 0.5) {
      breakPoint = remaining.lastIndexOf(" ", limit);
    }
    if (breakPoint < limit * 0.5) {
      breakPoint = limit;
    }

    chunks.push(remaining.slice(0, breakPoint));
    remaining = remaining.slice(breakPoint).trimStart();
  }

  return chunks;
}

/**
 * Get file extension from MIME type
 */
function getExtensionFromMime(mimeType: string): string {
  const mimeMap: Record<string, string> = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "audio/aac": ".aac",
    "audio/mp4": ".m4a",
    "audio/mpeg": ".mp3",
    "audio/ogg": ".ogg",
    "audio/wav": ".wav",
    "audio/webm": ".webm",
    "audio/x-m4a": ".m4a",
    "audio/m4a": ".m4a",
    "video/mp4": ".mp4",
    "video/webm": ".webm",
    "video/quicktime": ".mov",
    "application/pdf": ".pdf",
    "text/plain": ".txt",
  };
  return mimeMap[mimeType] || "";
}

/**
 * Transcribe audio file using Whisper CLI
 * Uses spawnSync with argument array to prevent command injection (RCE fix)
 */
function transcribeAudio(filePath: string, logger?: ChannelLogSink): string | null {
  try {
    // Get whisper path from env with fallback
    const whisperPath = process.env.WHISPER_PATH || "whisper";
    
    const outputDir = path.dirname(filePath);
    const baseName = path.basename(filePath, path.extname(filePath));

    // Run whisper transcription with spawnSync (no shell, argument array)
    logger?.info?.(`Transcribing audio file`);
    const result = spawnSync(whisperPath, [
      filePath,
      "--model", "small",
      "--language", "de",
      "--output_format", "txt",
      "--output_dir", outputDir
    ], {
      timeout: 120000, // 2 minute timeout
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "pipe"]
    });

    if (result.error) {
      // Check if whisper is not found
      if ((result.error as any).code === "ENOENT") {
        logger?.warn?.("Whisper not found, skipping transcription");
        return null;
      }
      throw result.error;
    }

    if (result.status !== 0) {
      logger?.error?.(`Whisper exited with code ${result.status}`);
      return null;
    }

    // Read the transcription output
    const txtPath = path.join(outputDir, `${baseName}.txt`);
    if (fs.existsSync(txtPath)) {
      const transcription = fs.readFileSync(txtPath, "utf-8").trim();
      // Clean up the txt file
      fs.unlinkSync(txtPath);
      // Don't log transcription content (log-redaction)
      logger?.info?.(`Transcription complete (${transcription.length} chars)`);
      return transcription;
    }
  } catch (err: any) {
    logger?.error?.(`Transcription failed: ${err.message}`);
  }
  return null;
}

/**
 * Process a received file message - download, decrypt, save, transcribe if audio
 */
async function processFileMessage(
  client: ThreemaClient,
  fileMsg: ThreemaFileMessage,
  from: string,
  logger?: ChannelLogSink
): Promise<{ filePath: string; transcription?: string } | null> {
  try {
    // Ensure media directory exists with secure permissions
    if (!fs.existsSync(MEDIA_INBOUND_DIR)) {
      fs.mkdirSync(MEDIA_INBOUND_DIR, { recursive: true });
      fs.chmodSync(MEDIA_INBOUND_DIR, 0o700);
    }

    // Download encrypted blob
    logger?.info?.(`Downloading blob (${fileMsg.s} bytes)`);
    logger?.debug?.(`Blob ID: ${fileMsg.b}`);
    const encryptedBlob = await client.downloadBlob(fileMsg.b);

    // Decrypt blob
    logger?.debug?.("Decrypting blob");
    const decryptedData = client.decryptBlob(encryptedBlob, fileMsg.k);
    if (!decryptedData) {
      logger?.error?.("Failed to decrypt blob");
      return null;
    }

    // Determine filename with sanitization
    const timestamp = Date.now();
    const ext = fileMsg.n
      ? path.extname(fileMsg.n)
      : getExtensionFromMime(fileMsg.m);
    const rawBaseName = fileMsg.n
      ? path.basename(fileMsg.n, path.extname(fileMsg.n))
      : `threema_${from}_${timestamp}`;
    // Sanitize filename to prevent path traversal and injection
    const baseName = sanitizeFilename(rawBaseName);
    const safeExt = sanitizeFilename(ext);
    const fileName = `${baseName}_${timestamp}${safeExt}`;
    const filePath = path.join(MEDIA_INBOUND_DIR, fileName);

    // Save to disk with restrictive permissions
    fs.writeFileSync(filePath, decryptedData, { mode: 0o600 });
    logger?.info?.(`Saved file (${fileMsg.m}, ${decryptedData.length} bytes)`);
    logger?.debug?.(`Saved file: ${fileName}`);

    // Transcribe if audio
    let transcription: string | undefined;
    if (AUDIO_MIME_TYPES.includes(fileMsg.m.toLowerCase())) {
      const result = transcribeAudio(filePath, logger);
      if (result) {
        transcription = result;
      }
    }

    return { filePath, transcription };
  } catch (err: any) {
    logger?.error?.(`Failed to process file message: ${err.message}`);
    return null;
  }
}

// ============================================================================
// Helper to get config from either location
// ============================================================================

function getThreemaConfig(config: OpenClawConfig): ThreemaConfig | undefined {
  const channelCfg = config?.channels?.threema;
  const pluginCfg = config?.plugins?.entries?.threema?.config;
  const cfg = channelCfg || pluginCfg;
  
  if (!cfg) return undefined;
  
  // Migrate legacy config values
  if ((cfg as any).dmPolicy === "pairing") {
    cfg.dmPolicy = "allowlist";
  }
  
  // Silently ignore removed fields (webhookSecret, etc.)
  // They may still be present in user's openclaw.json
  
  return cfg;
}

/**
 * Validate Threema ID format (8 uppercase alphanumeric characters)
 */
function isValidThreemaId(id: string): boolean {
  return /^[A-Z0-9*]{8}$/.test(id);
}

/**
 * Normalize a Threema target - extract ID from various formats
 */
function normalizeThreemaTarget(raw: string): string {
  // Remove threema: prefix if present
  let normalized = raw.replace(/^threema:/i, "").trim();
  // Uppercase the ID
  normalized = normalized.toUpperCase();
  return normalized;
}

/**
 * Get MIME type from file extension
 */
function getMimeFromPath(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase();
  const extMap: Record<string, string> = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".aac": "audio/aac",
    ".m4a": "audio/mp4",
    ".mp3": "audio/mpeg",
    ".ogg": "audio/ogg",
    ".wav": "audio/wav",
    ".webm": "audio/webm",
    ".mp4": "video/mp4",
    ".mov": "video/quicktime",
    ".pdf": "application/pdf",
    ".txt": "text/plain",
  };
  return extMap[ext] || "application/octet-stream";
}

// ============================================================================
// Channel Plugin Definition
// ============================================================================

// Shared status updater — allows the webhook handler (registered outside the
// channel adapter) to update the channel's health-monitor status on inbound events.
// startAccount populates this; the webhook handler calls updateActivity().
const channelStatus = {
  _getStatus: null as (() => ChannelAccountSnapshot) | null,
  _setStatus: null as ((s: ChannelAccountSnapshot) => void) | null,
  bind(getStatus: () => ChannelAccountSnapshot, setStatus: (s: ChannelAccountSnapshot) => void) {
    this._getStatus = getStatus;
    this._setStatus = setStatus;
  },
  updateActivity() {
    if (this._getStatus && this._setStatus) {
      const now = Date.now();
      this._setStatus({
        ...this._getStatus(),
        lastEventAt: now,
        lastInboundAt: now,
      });
    }
  },
};

const threemaChannel = {
  id: "threema" as const,

  meta: {
    id: "threema" as const,
    label: "Threema",
    selectionLabel: "Threema Gateway (E2E)",
    docsPath: "/channels/threema",
    blurb: "Privacy-focused Swiss messenger via Threema Gateway API.",
    aliases: ["threema-gateway"],
    order: 100, // After built-in channels
  },

  capabilities: {
    chatTypes: ["direct"] as const,
    media: true, // Now supports media!
    reactions: false,
    threads: false,
    polls: false,
    edit: false,
    unsend: false,
    reply: false,
    effects: false,
  },

  defaults: {
    queue: {
      debounceMs: 500,
    },
  },

  // ============================================================================
  // Config Adapter - Required for channel registration
  // ============================================================================
  config: {
    listAccountIds: (cfg: OpenClawConfig): string[] => {
      const threemaCfg = getThreemaConfig(cfg);
      return threemaCfg?.gatewayId ? ["default"] : [];
    },

    resolveAccount: (
      cfg: OpenClawConfig,
      accountId?: string | null
    ): ResolvedThreemaAccount => {
      const threemaCfg = getThreemaConfig(cfg);
      return {
        accountId: accountId ?? "default",
        gatewayId: threemaCfg?.gatewayId ?? "",
        secretKey: threemaCfg?.secretKey ?? "",
        privateKey: threemaCfg?.privateKey,
        enabled: threemaCfg?.enabled,
        webhookPath: threemaCfg?.webhookPath,
        dmPolicy: threemaCfg?.dmPolicy,
        allowFrom: threemaCfg?.allowFrom,
        textChunkLimit: threemaCfg?.textChunkLimit,
      };
    },

    isEnabled: (account: ResolvedThreemaAccount, cfg?: OpenClawConfig): boolean => {
      return account.enabled !== false && !!account.gatewayId;
    },

    isConfigured: (account: ResolvedThreemaAccount, cfg?: OpenClawConfig): boolean => {
      return !!(account.gatewayId && account.secretKey);
    },

    resolveAllowFrom: (params: {
      cfg: OpenClawConfig;
      accountId?: string | null;
    }): string[] | undefined => {
      const threemaCfg = getThreemaConfig(params.cfg);
      return threemaCfg?.allowFrom;
    },

    describeAccount: (
      account: ResolvedThreemaAccount,
      cfg?: OpenClawConfig
    ): ChannelAccountSnapshot => {
      return {
        accountId: account.accountId,
        name: account.gatewayId,
        enabled: account.enabled !== false,
        configured: !!(account.gatewayId && account.secretKey),
        linked: !!account.privateKey,
        webhookPath: account.webhookPath,
      };
    },
  },

  // ============================================================================
  // Outbound Adapter - Critical for message tool to work
  // ============================================================================
  outbound: {
    deliveryMode: "direct" as const,
    textChunkLimit: 3500,
    chunkerMode: "text" as const,

    // Text chunker for long messages
    chunker: (text: string, limit: number): string[] => {
      return chunkText(text, limit);
    },

    // Target resolution - validates Threema IDs
    resolveTarget: (params: {
      cfg?: OpenClawConfig;
      to?: string;
      allowFrom?: string[];
      accountId?: string | null;
      mode?: "explicit" | "implicit" | "heartbeat";
    }): { ok: true; to: string } | { ok: false; error: Error } => {
      const raw = params.to?.trim();

      if (!raw) {
        return {
          ok: false,
          error: new Error(
            "Threema target required. Provide an 8-character Threema ID (e.g., XXXX1234)."
          ),
        };
      }

      const normalized = normalizeThreemaTarget(raw);

      if (!isValidThreemaId(normalized)) {
        return {
          ok: false,
          error: new Error(
            `Invalid Threema ID "${raw}". Expected 8 uppercase alphanumeric characters.`
          ),
        };
      }

      // For explicit mode, validate against allowlist if configured
      if (params.mode === "explicit" && params.allowFrom?.length) {
        const normalizedAllowFrom = params.allowFrom.map((id) =>
          normalizeThreemaTarget(id)
        );
        if (!normalizedAllowFrom.includes(normalized)) {
          return {
            ok: false,
            error: new Error(
              `Threema ID "${normalized}" not in allowlist. Add to channels.threema.allowFrom or use /approve.`
            ),
          };
        }
      }

      return { ok: true, to: normalized };
    },

    // Send text message
    sendText: async (
      ctx: ChannelOutboundContext
    ): Promise<OutboundDeliveryResult> => {
      const threemaCfg = getThreemaConfig(ctx.cfg);
      if (!threemaCfg?.gatewayId || !threemaCfg?.secretKey) {
        throw new Error(
          "Threema not configured: missing gatewayId or secretKey"
        );
      }

      const client = new ThreemaClient(threemaCfg);
      const to = normalizeThreemaTarget(ctx.to);

      let messageId: string;
      if (client.isE2EEnabled) {
        messageId = await client.sendE2E(to, ctx.text);
      } else {
        messageId = await client.sendSimple(to, ctx.text);
      }

      return {
        channel: "threema",
        messageId: messageId.trim(),
        chatId: to,
        timestamp: Date.now(),
      };
    },

    // Send media (file message)
    sendMedia: async (
      ctx: ChannelOutboundContext
    ): Promise<OutboundDeliveryResult> => {
      const threemaCfg = getThreemaConfig(ctx.cfg);
      if (!threemaCfg?.gatewayId || !threemaCfg?.secretKey) {
        throw new Error(
          "Threema not configured: missing gatewayId or secretKey"
        );
      }

      const client = new ThreemaClient(threemaCfg);
      const to = normalizeThreemaTarget(ctx.to);

      if (!client.isE2EEnabled) {
        throw new Error("Threema media sending requires E2E mode (privateKey)");
      }

      if (!ctx.mediaUrl) {
        throw new Error("No media URL provided");
      }

      // Handle local file paths and URLs
      let filePath: string;
      let tempFilePath: string | null = null; // Track temp file for cleanup
      
      try {
        if (
          ctx.mediaUrl.startsWith("/") ||
          ctx.mediaUrl.startsWith("file://")
        ) {
          // Local file path - validate it's within allowed media directory
          const rawPath = ctx.mediaUrl.replace("file://", "");
          const validation = validateLocalMediaPath(rawPath);
          if (!validation.valid) {
            throw new Error(validation.error || "Local file path not allowed outside media directory");
          }
          filePath = validation.realPath!;
        } else if (ctx.mediaUrl.startsWith("https://")) {
          // Only allow HTTPS URLs (no HTTP for security)
          
          // SSRF protection: block private/internal IPs (hostname check)
          if (isPrivateUrl(ctx.mediaUrl)) {
            throw new Error("Private/internal URLs not allowed for security.");
          }
          
          // DNS rebinding protection: resolve hostname and check resolved IP
          const parsed = new URL(ctx.mediaUrl);
          const dnsCheck = await resolveAndCheckPrivate(parsed.hostname);
          if (dnsCheck.isPrivate) {
            throw new Error(`URL resolves to private/internal IP (${dnsCheck.resolvedIP || "blocked domain"})`);
          }
          
          const tempDir = path.join(
            process.env.HOME || "/tmp",
            ".openclaw",
            "media",
            "temp"
          );
          if (!fs.existsSync(tempDir)) {
            fs.mkdirSync(tempDir, { recursive: true, mode: 0o700 });
          }
          
          // Fetch with timeout and size limit
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 15000); // 15s timeout
          
          try {
            const res = await fetch(ctx.mediaUrl, { signal: controller.signal, redirect: "error" });
            
            if (!res.ok) {
              throw new Error(`Failed to download media: ${res.status}`);
            }
            
            // DoS protection: check Content-Length before downloading
            const contentLength = res.headers.get("content-length");
            const MAX_MEDIA_SIZE = 50 * 1024 * 1024; // 50MB
            if (contentLength && parseInt(contentLength, 10) > MAX_MEDIA_SIZE) {
              throw new Error(`Media too large (${contentLength} bytes > 50MB limit)`);
            }
            
            const buffer = await res.arrayBuffer();
            clearTimeout(timeoutId); // Clear AFTER full download completes
            
            // Also check actual size after download
            if (buffer.byteLength > MAX_MEDIA_SIZE) {
              throw new Error(`Media too large (${buffer.byteLength} bytes > 50MB limit)`);
            }
            
            const urlPath = new URL(ctx.mediaUrl).pathname;
            const rawFileName = path.basename(urlPath) || `media_${Date.now()}`;
            // Sanitize downloaded filename
            const fileName = sanitizeFilename(rawFileName);
            filePath = path.join(tempDir, fileName);
            tempFilePath = filePath; // Mark for cleanup
            fs.writeFileSync(filePath, new Uint8Array(buffer), { mode: 0o600 });
          } catch (err: any) {
            clearTimeout(timeoutId);
            if (err.name === "AbortError") {
              throw new Error("Media download timed out (15s)");
            }
            throw err;
          }
        } else if (ctx.mediaUrl.startsWith("http://")) {
          throw new Error("HTTP URLs not allowed for security. Use HTTPS.");
        } else {
          throw new Error(`Unsupported media URL format: ${ctx.mediaUrl}`);
        }

        if (!fs.existsSync(filePath)) {
          throw new Error(`Media file not found: ${filePath}`);
        }

        const mimeType = getMimeFromPath(filePath);
        const caption = ctx.text || undefined;

        const messageId = await client.sendFileE2E(to, filePath, mimeType, caption);

        return {
          channel: "threema",
          messageId: messageId.trim(),
          chatId: to,
          timestamp: Date.now(),
        };
      } finally {
        // Cleanup temp file
        if (tempFilePath && fs.existsSync(tempFilePath)) {
          try {
            fs.unlinkSync(tempFilePath);
          } catch {
            // Ignore cleanup errors
          }
        }
      }
    },
  },

  // ============================================================================
  // Messaging Adapter - For target formatting and hints
  // ============================================================================
  messaging: {
    normalizeTarget: (raw: string): string | undefined => {
      const normalized = normalizeThreemaTarget(raw);
      return isValidThreemaId(normalized) ? normalized : undefined;
    },

    targetResolver: {
      looksLikeId: (raw: string, normalized?: string): boolean => {
        const id = normalized ?? normalizeThreemaTarget(raw);
        return isValidThreemaId(id);
      },
      hint: "Threema ID (8 uppercase chars, e.g., XXXX1234)",
    },

    formatTargetDisplay: (params: {
      target: string;
      display?: string;
    }): string => {
      return params.display ?? params.target;
    },
  },

  // ============================================================================
  // Security Adapter
  // ============================================================================
  security: {
    resolveDmPolicy: (ctx: {
      cfg: OpenClawConfig;
      accountId?: string | null;
      account: ResolvedThreemaAccount;
    }) => {
      const policy = ctx.account.dmPolicy ?? "allowlist";
      const allowFrom = ctx.account.allowFrom;
      return {
        policy,
        allowFrom: allowFrom ?? null,
        allowFromPath: "channels.threema.allowFrom",
        approveHint: "Add Threema ID to channels.threema.allowFrom in config",
        normalizeEntry: normalizeThreemaTarget,
      };
    },
  },

  // ============================================================================
  // Pairing Adapter
  // ============================================================================
  pairing: {
    idLabel: "Threema ID",
    normalizeAllowEntry: normalizeThreemaTarget,
  },

  // ============================================================================
  // Status Adapter
  // ============================================================================
  status: {
    defaultRuntime: {
      accountId: "default",
      running: false,
      connected: false,
    } as ChannelAccountSnapshot,

    buildAccountSnapshot: (params: {
      account: ResolvedThreemaAccount;
      cfg: OpenClawConfig;
      runtime?: ChannelAccountSnapshot;
    }): ChannelAccountSnapshot => {
      const { account, runtime } = params;
      return {
        accountId: account.accountId,
        name: account.gatewayId,
        enabled: account.enabled !== false,
        configured: !!(account.gatewayId && account.secretKey),
        linked: !!account.privateKey,
        running: runtime?.running ?? false,
        connected: runtime?.connected ?? false,
        lastConnectedAt: runtime?.lastConnectedAt,
        webhookPath: account.webhookPath,
      };
    },

    resolveAccountState: (params: {
      account: ResolvedThreemaAccount;
      cfg: OpenClawConfig;
      configured: boolean;
      enabled: boolean;
    }):
      | "linked"
      | "not linked"
      | "configured"
      | "not configured"
      | "enabled"
      | "disabled" => {
      if (!params.enabled) return "disabled";
      if (!params.configured) return "not configured";
      if (params.account.privateKey) return "linked";
      return "configured";
    },
  },

  // ============================================================================
  // Gateway Adapter - For starting/stopping the channel service
  // ============================================================================
  gateway: {
    startAccount: async (ctx: ChannelGatewayContext): Promise<void> => {
      const { account, cfg, log, setStatus, getStatus, abortSignal } = ctx;

      if (!account.gatewayId || !account.secretKey) {
        log?.warn?.("Threema not configured - missing gatewayId or secretKey");
        return;
      }

      const client = new ThreemaClient(account);

      log?.info?.(
        `Threema Gateway starting: ${account.gatewayId} (${client.isE2EEnabled ? "E2E" : "Basic"} mode)`
      );

      if (client.isE2EEnabled) {
        log?.info?.(`E2E public key: ${client.ownPublicKey}`);
      }

      // Bind shared status so the webhook handler can report activity
      channelStatus.bind(getStatus, setStatus);

      setStatus({
        ...getStatus(),
        running: true,
        connected: true,
        lastConnectedAt: Date.now(),
        lastEventAt: Date.now(),
      } as any);

      // Periodic health heartbeat — update lastEventAt every 15 min so the
      // health-monitor doesn't think we're stuck (webhook channels are passive).
      const heartbeatInterval = setInterval(() => {
        setStatus({
          ...getStatus(),
          lastEventAt: Date.now(),
        } as any);
      }, 15 * 60 * 1000);

      // Keep the promise alive until abortSignal fires — resolving immediately
      // causes the gateway to treat the channel as "exited" and restart it.
      await new Promise<void>((resolve) => {
        if (abortSignal.aborted) return resolve();
        abortSignal.addEventListener("abort", () => {
          clearInterval(heartbeatInterval);
          resolve();
        }, { once: true });
      });

      log?.info?.("Threema Gateway stopped via abort signal");
    },

    stopAccount: async (ctx: ChannelGatewayContext): Promise<void> => {
      const { setStatus, getStatus, log } = ctx;
      log?.info?.("Threema Gateway stopping");
      setStatus({
        ...getStatus(),
        running: false,
        connected: false,
      });
    },
  },
};
