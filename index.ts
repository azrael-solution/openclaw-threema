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
import { execSync } from "child_process";

// ============================================================================
// Types (matching OpenClaw's expected interfaces)
// ============================================================================

interface ThreemaConfig {
  enabled?: boolean;
  gatewayId: string;
  secretKey: string;
  privateKey?: string; // hex-encoded NaCl private key for E2E
  webhookPath?: string;
  webhookSecret?: string;
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

    // Create message payload (type 0x01 = text)
    const textBytes = decodeUTF8(text);
    const paddedLen = Math.ceil((textBytes.length + 1) / 256) * 256;
    const payload = new Uint8Array(paddedLen);
    payload[0] = 0x01; // Text message type
    payload.set(textBytes, 1);
    // Fill with PKCS7-style padding
    const padByte = paddedLen - textBytes.length - 1;
    for (let i = textBytes.length + 1; i < paddedLen; i++) {
      payload[i] = padByte;
    }

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

    const res = await fetch(`${THREEMA_API_BASE}/send_e2e`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString(),
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Threema E2E API error ${res.status}: ${errText}`);
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

    // Create E2E payload (type 0x17 = file message)
    const paddedLen = Math.ceil((fileMsgBytes.length + 1) / 256) * 256;
    const payload = new Uint8Array(paddedLen);
    payload[0] = 0x17; // File message type
    payload.set(fileMsgBytes, 1);
    // Fill with PKCS7-style padding
    const padByte = paddedLen - fileMsgBytes.length - 1;
    for (let i = fileMsgBytes.length + 1; i < paddedLen; i++) {
      payload[i] = padByte;
    }

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

    const res = await fetch(`${THREEMA_API_BASE}/send_e2e`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString(),
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Threema E2E API error ${res.status}: ${errText}`);
    }

    return res.text();
  }

  /**
   * Upload an encrypted blob to Threema servers
   */
  async uploadBlob(encryptedData: Uint8Array): Promise<string> {
    const formData = new FormData();
    formData.append("blob", new Blob([encryptedData]), "blob");

    const url = `${THREEMA_API_BASE}/upload_blob?from=${this.gatewayId}&secret=${this.secretKey}`;

    const res = await fetch(url, {
      method: "POST",
      body: formData,
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Threema blob upload error ${res.status}: ${errText}`);
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
      const errText = await res.text();
      throw new Error(`Threema blob download error ${res.status}: ${errText}`);
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
   * Send a text message (Basic mode - server-side encryption)
   */
  async sendSimple(to: string, text: string): Promise<string> {
    const params = new URLSearchParams({
      from: this.gatewayId,
      to,
      text,
      secret: this.secretKey,
    });

    const res = await fetch(`${THREEMA_API_BASE}/send_simple`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString(),
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Threema API error ${res.status}: ${errText}`);
    }

    return res.text();
  }

  /**
   * Get public key for a Threema ID
   */
  async getPublicKey(threemaId: string): Promise<Uint8Array> {
    const cached = this.publicKeyCache.get(threemaId);
    if (cached) return cached;

    const res = await fetch(
      `${THREEMA_API_BASE}/pubkeys/${threemaId}?from=${this.gatewayId}&secret=${this.secretKey}`
    );

    if (!res.ok) {
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

    const type = decrypted[0];

    // Remove PKCS7 padding
    const padByte = decrypted[decrypted.length - 1];
    const unpaddedLen = decrypted.length - padByte;
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
 */
function transcribeAudio(filePath: string, logger?: ChannelLogSink): string | null {
  try {
    // Check if whisper is available
    const whisperPath = "/home/linuxbrew/.linuxbrew/bin/whisper";
    if (!fs.existsSync(whisperPath)) {
      logger?.warn?.("Whisper not found, skipping transcription");
      return null;
    }

    const outputDir = path.dirname(filePath);
    const baseName = path.basename(filePath, path.extname(filePath));

    // Run whisper transcription
    logger?.info?.(`Transcribing audio: ${filePath}`);
    execSync(
      `${whisperPath} "${filePath}" --model small --language de --output_format txt --output_dir "${outputDir}" 2>&1`,
      { timeout: 120000 } // 2 minute timeout
    );

    // Read the transcription output
    const txtPath = path.join(outputDir, `${baseName}.txt`);
    if (fs.existsSync(txtPath)) {
      const transcription = fs.readFileSync(txtPath, "utf-8").trim();
      // Clean up the txt file
      fs.unlinkSync(txtPath);
      logger?.info?.(`Transcription complete: ${transcription.slice(0, 100)}...`);
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
    // Ensure media directory exists
    if (!fs.existsSync(MEDIA_INBOUND_DIR)) {
      fs.mkdirSync(MEDIA_INBOUND_DIR, { recursive: true });
    }

    // Download encrypted blob
    logger?.info?.(`Downloading blob ${fileMsg.b} (${fileMsg.s} bytes)`);
    const encryptedBlob = await client.downloadBlob(fileMsg.b);

    // Decrypt blob
    logger?.info?.(`Decrypting blob with key`);
    const decryptedData = client.decryptBlob(encryptedBlob, fileMsg.k);
    if (!decryptedData) {
      logger?.error?.("Failed to decrypt blob");
      return null;
    }

    // Determine filename
    const timestamp = Date.now();
    const ext = fileMsg.n
      ? path.extname(fileMsg.n)
      : getExtensionFromMime(fileMsg.m);
    const baseName = fileMsg.n
      ? path.basename(fileMsg.n, path.extname(fileMsg.n))
      : `threema_${from}_${timestamp}`;
    const fileName = `${baseName}_${timestamp}${ext}`;
    const filePath = path.join(MEDIA_INBOUND_DIR, fileName);

    // Save to disk
    fs.writeFileSync(filePath, decryptedData);
    logger?.info?.(`Saved file: ${filePath} (${fileMsg.m})`);

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
  return channelCfg || pluginCfg;
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

async function parseBody(req: any): Promise<any> {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk: string) => {
      data += chunk;
    });
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
        webhookSecret: threemaCfg?.webhookSecret,
        dmPolicy: threemaCfg?.dmPolicy,
        allowFrom: threemaCfg?.allowFrom,
        textChunkLimit: threemaCfg?.textChunkLimit,
      };
    },

    isEnabled: (account: ResolvedThreemaAccount): boolean => {
      return account.enabled !== false && !!account.gatewayId;
    },

    isConfigured: (account: ResolvedThreemaAccount): boolean => {
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
      account: ResolvedThreemaAccount
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
      if (
        ctx.mediaUrl.startsWith("/") ||
        ctx.mediaUrl.startsWith("file://")
      ) {
        filePath = ctx.mediaUrl.replace("file://", "");
      } else if (
        ctx.mediaUrl.startsWith("http://") ||
        ctx.mediaUrl.startsWith("https://")
      ) {
        // Download remote file to temp location
        const tempDir = path.join(
          process.env.HOME || "/tmp",
          ".openclaw",
          "media",
          "temp"
        );
        if (!fs.existsSync(tempDir)) {
          fs.mkdirSync(tempDir, { recursive: true });
        }
        const res = await fetch(ctx.mediaUrl);
        if (!res.ok) {
          throw new Error(`Failed to download media: ${res.status}`);
        }
        const buffer = await res.arrayBuffer();
        const urlPath = new URL(ctx.mediaUrl).pathname;
        const fileName = path.basename(urlPath) || `media_${Date.now()}`;
        filePath = path.join(tempDir, fileName);
        fs.writeFileSync(filePath, new Uint8Array(buffer));
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
      const policy = ctx.account.dmPolicy ?? "pairing";
      const allowFrom = ctx.account.allowFrom;
      return {
        policy,
        allowFrom: allowFrom ?? null,
        allowFromPath: "channels.threema.allowFrom",
        approveHint: "Send /pair to start pairing",
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
      const { account, cfg, log, setStatus, getStatus } = ctx;

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

      setStatus({
        ...getStatus(),
        running: true,
        connected: true,
        lastConnectedAt: Date.now(),
      });
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

// ============================================================================
// Plugin Registration
// ============================================================================

export const id = "threema";
export const name = "Threema Gateway";
export const version = "0.3.0";
export const description =
  "Threema messaging channel via Threema Gateway API (E2E encrypted, with media support)";

export default function register(api: any) {
  const config = api.config as OpenClawConfig;
  const threemaCfg = getThreemaConfig(config);
  const runtime = api.runtime;

  // Register the channel plugin
  api.registerChannel({ plugin: threemaChannel });
  api.logger?.info?.("Threema channel plugin registered");

  // Register webhook handler for incoming E2E messages
  if (threemaCfg?.privateKey && threemaCfg?.webhookPath) {
    const client = new ThreemaClient(threemaCfg);
    const webhookPath = threemaCfg.webhookPath;

    api.registerHttpRoute?.({
      path: webhookPath,
      handler: async (req: any, res: any) => {
        // Only accept POST requests
        if (req.method !== "POST") {
          res.writeHead(405, { "Content-Type": "text/plain" });
          res.end("Method Not Allowed");
          return;
        }

        try {
          const body = await parseBody(req);
          api.logger?.info?.(`Threema webhook: ${JSON.stringify(body)}`);

          const { from, nonce, box, nickname, messageId } = body;
          if (!from || !nonce || !box) {
            res.writeHead(400, { "Content-Type": "text/plain" });
            res.end("Missing required parameters: from, nonce, box");
            return;
          }

          // Decrypt the message
          const senderPubKey = await client.getPublicKey(from);
          const decrypted = client.decryptMessage(
            senderPubKey,
            hexToBytes(nonce),
            hexToBytes(box)
          );

          const senderLabel = nickname || from;

          if (decrypted?.type === 0x01 && decrypted?.text) {
            // Text message
            api.logger?.info?.(
              `Threema text from ${from} (${senderLabel}): ${decrypted.text}`
            );

            // Dispatch to OpenClaw via enqueueSystemEvent
            const enqueue = runtime?.system?.enqueueSystemEvent;
            if (enqueue) {
              const envelope = `[Threema message from ${senderLabel} (${from})]\n${decrypted.text}`;
              enqueue(envelope, {
                sessionKey: "agent:main:main",
                deliveryContext: {
                  channel: "threema",
                  to: from,
                  from: from,
                  accountId: "default",
                },
              });
              api.logger?.info?.(
                "Threema message dispatched via enqueueSystemEvent"
              );

              // Wake the agent
              wakeAgent(config);
            } else {
              api.logger?.warn?.("enqueueSystemEvent not available");
            }
          } else if (decrypted?.type === 0x17 && decrypted?.fileMessage) {
            // File message
            const fileMsg = decrypted.fileMessage;
            api.logger?.info?.(
              `Threema file from ${from}: ${fileMsg.m} (${fileMsg.s} bytes)${fileMsg.d ? ` - "${fileMsg.d}"` : ""}`
            );

            // Process the file: download, decrypt, save, maybe transcribe
            const result = await processFileMessage(
              client,
              fileMsg,
              from,
              api.logger
            );

            // Dispatch to OpenClaw
            const enqueue = runtime?.system?.enqueueSystemEvent;
            if (enqueue) {
              let envelope = `[Threema file from ${senderLabel} (${from})]`;

              if (fileMsg.d) {
                envelope += `\nCaption: ${fileMsg.d}`;
              }

              envelope += `\nFile: ${fileMsg.n || "unnamed"} (${fileMsg.m}, ${fileMsg.s} bytes)`;

              if (result?.filePath) {
                envelope += `\nSaved to: ${result.filePath}`;

                if (result.transcription) {
                  envelope += `\n\n🎤 Audio transcription:\n${result.transcription}`;
                }
              } else {
                envelope += `\n⚠️ Failed to download/decrypt file`;
              }

              enqueue(envelope, {
                sessionKey: "agent:main:main",
                deliveryContext: {
                  channel: "threema",
                  to: from,
                  from: from,
                  accountId: "default",
                  mediaPath: result?.filePath,
                  transcription: result?.transcription,
                },
              });
              api.logger?.info?.(
                "Threema file message dispatched via enqueueSystemEvent"
              );

              // Wake the agent
              wakeAgent(config);
            }
          } else if (decrypted?.type === 0x80) {
            // Delivery receipt
            const statusNames: Record<number, string> = {
              1: "received",
              2: "read",
              3: "acknowledged",
              4: "declined",
            };
            api.logger?.info?.(
              `Threema delivery receipt from ${from}: ${statusNames[decrypted.status || 0] || "unknown"}`
            );
          } else if (decrypted) {
            api.logger?.info?.(
              `Threema message type 0x${decrypted.type.toString(16)} from ${from} (not yet supported)`
            );
          }

          res.writeHead(200, { "Content-Type": "text/plain" });
          res.end("OK");
        } catch (err: any) {
          api.logger?.error?.(`Threema webhook error: ${err.message}`);
          res.writeHead(500, { "Content-Type": "text/plain" });
          res.end("Internal Server Error");
        }
      },
    });
    api.logger?.info?.(`Threema webhook registered at ${webhookPath}`);
  }

  // Register CLI commands
  api.registerCli?.(
    ({ program }: any) => {
      const threema = program
        .command("threema")
        .description("Threema Gateway utilities");

      threema
        .command("keygen")
        .description("Generate a new NaCl key pair for E2E mode")
        .action(() => {
          const keys = generateKeyPair();
          console.log("\n🔑 Generated Threema E2E Key Pair\n");
          console.log("Private Key (keep secret!):");
          console.log(`  ${keys.privateKey}\n`);
          console.log("Public Key (share with contacts):");
          console.log(`  ${keys.publicKey}\n`);
          console.log("Add to config:");
          console.log(
            `  channels.threema.privateKey = "${keys.privateKey}"\n`
          );
        });

      threema
        .command("send <to> <message>")
        .description("Send a test message")
        .action(async (to: string, message: string) => {
          if (!threemaCfg?.gatewayId) {
            console.error("Threema not configured");
            process.exit(1);
          }

          const client = new ThreemaClient(threemaCfg);
          const normalizedTo = normalizeThreemaTarget(to);

          try {
            const msgId = client.isE2EEnabled
              ? await client.sendE2E(normalizedTo, message)
              : await client.sendSimple(normalizedTo, message);
            console.log(
              `✓ Message sent to ${normalizedTo} (ID: ${msgId.trim()})`
            );
          } catch (err: any) {
            console.error(`✗ Send failed: ${err.message}`);
            process.exit(1);
          }
        });

      threema
        .command("send-file <to> <filepath>")
        .description("Send a file (E2E mode only)")
        .option("-c, --caption <text>", "Caption for the file")
        .action(async (to: string, filepath: string, opts: any) => {
          if (!threemaCfg?.gatewayId || !threemaCfg?.privateKey) {
            console.error("Threema E2E not configured");
            process.exit(1);
          }

          const client = new ThreemaClient(threemaCfg);
          const normalizedTo = normalizeThreemaTarget(to);

          if (!fs.existsSync(filepath)) {
            console.error(`File not found: ${filepath}`);
            process.exit(1);
          }

          const mimeType = getMimeFromPath(filepath);

          try {
            const msgId = await client.sendFileE2E(
              normalizedTo,
              filepath,
              mimeType,
              opts.caption
            );
            console.log(
              `✓ File sent to ${normalizedTo} (ID: ${msgId.trim()})`
            );
          } catch (err: any) {
            console.error(`✗ Send failed: ${err.message}`);
            process.exit(1);
          }
        });

      threema
        .command("status")
        .description("Show Threema Gateway status")
        .action(() => {
          if (!threemaCfg?.gatewayId) {
            console.log("❌ Threema not configured");
            return;
          }

          console.log(`\n📱 Threema Gateway Status\n`);
          console.log(`Gateway ID: ${threemaCfg.gatewayId}`);
          console.log(
            `Mode: ${threemaCfg.privateKey ? "E2E (encrypted)" : "Basic (server-side)"}`
          );
          console.log(`DM Policy: ${threemaCfg.dmPolicy ?? "pairing"}`);
          console.log(
            `Webhook: ${threemaCfg.webhookPath ?? "(not configured)"}`
          );
          console.log(`Media support: ✅ enabled`);

          if (threemaCfg.allowFrom?.length) {
            console.log(`Allowed: ${threemaCfg.allowFrom.join(", ")}`);
          }
          console.log();
        });
    },
    { commands: ["threema"] }
  );

  api.logger?.info?.("Threema Gateway plugin loaded (with media support)");
}

/**
 * Wake the agent to process new messages
 */
function wakeAgent(config: any) {
  const gatewayPort = config?.gateway?.port || 18789;
  // Read hooks token from config file directly (config object may have redacted values)
  let hooksToken: string | undefined;
  try {
    const rawConfig = JSON.parse(fs.readFileSync(
      path.join(process.env.HOME || "/tmp", ".openclaw", "openclaw.json"), "utf8"
    ));
    hooksToken = rawConfig?.hooks?.token;
  } catch {}
  if (!hooksToken) return;
  const wakeUrl = `http://127.0.0.1:${gatewayPort}/hooks/wake`;
  const wakeBody = JSON.stringify({
    text: "Threema message received",
    mode: "now",
  });
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "Authorization": `Bearer ${hooksToken}`,
  };
  fetch(wakeUrl, { method: "POST", headers, body: wakeBody })
    .then(res => {
      if (!res.ok) res.text().then(t => console.error(`[Threema] Wake failed: ${res.status} ${t}`));
    })
    .catch(err => console.error(`[Threema] Wake error: ${err.message}`));
}
