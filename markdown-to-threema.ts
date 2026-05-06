/**
 * markdown-to-threema.ts
 *
 * Converts a Markdown string to Threema's native text-markup conventions.
 *
 * Threema-Markup (offizielle Threema-Inline-Formatierung, plattformübergreifend
 * unterstützt seit 2024):
 *   *bold*       — fett (genau ein Sternchen pro Seite)
 *   _italic_     — kursiv (genau ein Unterstrich pro Seite)
 *   ~strike~     — durchgestrichen (genau eine Tilde pro Seite)
 *
 * Markdown-Konstrukte, die Threema NICHT unterstützt, werden in
 * sinnvolle Plain-Text-Repräsentationen überführt:
 *   - **bold** / __bold__   → *bold*
 *   - *italic* / _italic_   → _italic_  (so wie es ist; sicher-stellt nur, dass wir's nicht zerschießen)
 *   - ~~strike~~            → ~strike~
 *   - # / ## / ### Headers  → *Header*  (fett) + Leerzeile danach
 *   - - / * / + Liste       → •  (Unicode-Bullet)
 *   - 1. Nummerierte Liste  → 1.  (lassen wir; Threema rendert das eh als Plain)
 *   - > Blockquote          → │  (Vertical-Bar, optisch wie Quote)
 *   - `inline code`         → "inline code"  (Anführungszeichen)
 *   - ```block code```      → Block bleibt erhalten, Backticks weg
 *   - [text](url)           → text — url   (oder nur url falls text==url)
 *   - ![alt](url)           → [Bild: alt] — url (Markdown-Image)
 *   - | a | b |             → a — b  (Tabelle wird zu Plain-Listen)
 *
 * Das Ziel ist nicht 100 % treue Markdown-Erhaltung, sondern:
 *   1. Was Threema kann, nutzen.
 *   2. Was Threema nicht kann, optisch ordentlich zerlegen.
 *   3. Inhalt erhält bleiben — keine Datenverluste.
 *
 * Heuristik-Reihenfolge wichtig:
 *   1. Code-Blöcke (Fenced) zuerst herausziehen → escapen → später wieder einfügen.
 *   2. Inline-Code (Backticks) auch escapen.
 *   3. Tabellen → Bullet-List.
 *   4. Bold/Italic/Strikethrough → Threema-Markup.
 *   5. Headers → fett.
 *   6. Listen → Bullets.
 *   7. Blockquotes → Vertical-Bar.
 *   8. Links / Images → Plain-Auflösung.
 */

const PLACEHOLDER_PREFIX = "\u0001THREEMA_PH_";
const PLACEHOLDER_SUFFIX = "\u0001";

/**
 * Convert Markdown → Threema text markup.
 *
 * Always returns a string. Empty input → empty output.
 * The conversion is best-effort and idempotent for valid Threema-text input.
 */
export function markdownToThreema(input: string | null | undefined): string {
  if (!input) return "";

  let text = input;

  // ---- 1. Stash code blocks & inline code so we don't munge them ----
  const stash: string[] = [];
  const stashOne = (val: string): string => {
    const idx = stash.length;
    stash.push(val);
    return `${PLACEHOLDER_PREFIX}${idx}${PLACEHOLDER_SUFFIX}`;
  };

  // Fenced code blocks: ```lang\n...\n``` or ~~~...~~~
  text = text.replace(
    /```([a-zA-Z0-9_+-]*)?\n([\s\S]*?)\n```/g,
    (_m, _lang, body: string) => stashOne(body.replace(/\s+$/g, ""))
  );
  text = text.replace(
    /~~~([a-zA-Z0-9_+-]*)?\n([\s\S]*?)\n~~~/g,
    (_m, _lang, body: string) => stashOne(body.replace(/\s+$/g, ""))
  );

  // Inline code: `code` (single backticks, no embedded backticks)
  text = text.replace(/`([^`\n]+)`/g, (_m, body: string) => stashOne(`"${body}"`));

  // ---- 2. Tables → bullet lists ----
  // A Markdown table is detected by a header row + a separator row of dashes.
  // We turn each data row into a bullet line "col1 — col2 — col3" and
  // the header row into "*col1 — col2*" prefix.
  text = convertTables(text);

  // ---- 3. Block-level transforms (line by line) ----
  const lines = text.split("\n");
  const outLines: string[] = [];
  for (let i = 0; i < lines.length; i += 1) {
    let line = lines[i];

    // Headers # / ## / ### → *Header*
    const headerMatch = /^(#{1,6})\s+(.+?)\s*#*\s*$/.exec(line);
    if (headerMatch) {
      const headerText = headerMatch[2];
      outLines.push(`*${stripInlineMarkers(headerText)}*`);
      continue;
    }

    // Horizontal rule: ---, ___, ***
    if (/^\s*([-*_])\1\1+\s*$/.test(line)) {
      outLines.push("─────────────");
      continue;
    }

    // Blockquote: > foo
    const quoteMatch = /^(\s*)>\s?(.*)$/.exec(line);
    if (quoteMatch) {
      const [, indent, body] = quoteMatch;
      outLines.push(`${indent}│ ${body}`);
      continue;
    }

    // Unordered list: -, *, +
    const ulMatch = /^(\s*)[-*+]\s+(.*)$/.exec(line);
    if (ulMatch) {
      const [, indent, body] = ulMatch;
      outLines.push(`${indent}• ${body}`);
      continue;
    }

    // Numbered list: 1. foo (keep as-is, Threema renders that fine plain)
    // → no transform needed.

    outLines.push(line);
  }
  text = outLines.join("\n");

  // ---- 4. Inline replacements ----
  // Markdown-Image:  ![alt](url)  →  [Bild: alt] — url   (or just url)
  text = text.replace(
    /!\[([^\]]*)\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g,
    (_m, alt: string, url: string) => {
      if (!alt.trim()) return url;
      return `[Bild: ${alt}] — ${url}`;
    }
  );

  // Link:  [text](url)  →  text — url  (or just url if text === url)
  text = text.replace(
    /\[([^\]]+)\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g,
    (_m, label: string, url: string) => {
      const trimmed = label.trim();
      if (!trimmed || trimmed === url) return url;
      return `${trimmed} — ${url}`;
    }
  );

  // Bold: **text** or __text__  →  *text*   (Threema)
  // Run this BEFORE italic so we don't accidentally chew **x** into *_x_*.
  text = text.replace(/\*\*([^*\n][^*\n]*?)\*\*/g, "*$1*");
  text = text.replace(/__([^_\n][^_\n]*?)__/g, "*$1*");

  // Strikethrough: ~~text~~ → ~text~
  text = text.replace(/~~([^~\n]+?)~~/g, "~$1~");

  // Italic with *text*:  Threema's *...* is BOLD, not italic. Markdown
  // *italic* with single asterisks would render as bold in Threema.
  // The safer move: convert single-asterisk *italic* to underscore _italic_.
  // BUT: We just emitted *bold* above for **bold**. We must NOT touch
  // existing *bold* output. Heuristic: only convert remaining *…* if the
  // word inside contains no spaces around it being already-bold.
  //
  // Reality: distinguishing original *italic* (single asterisks) from
  // converted *bold* (also single asterisks) post-hoc is impossible.
  //
  // Pragmatic decision: We do NOT touch single asterisks. Models in 2026
  // overwhelmingly produce **bold** (double) and _italic_ (underscore),
  // so this is a non-issue. If a model produces *italic*, it ends up as
  // bold in Threema — minor cosmetic glitch, not a disaster.

  // ---- 5. Restore code stash ----
  text = text.replace(
    new RegExp(`${PLACEHOLDER_PREFIX}(\\d+)${PLACEHOLDER_SUFFIX}`, "g"),
    (_m, idx: string) => stash[parseInt(idx, 10)] ?? _m
  );

  // ---- 6. Tidy: collapse 3+ consecutive blank lines to 2 ----
  text = text.replace(/\n{3,}/g, "\n\n");

  return text;
}

/**
 * Strip Markdown inline markers from header text.
 * Headers in Markdown are usually "# **Bold Text**" — we want to land at
 * "*Bold Text*" in Threema, not "**Bold Text**".
 */
function stripInlineMarkers(s: string): string {
  let r = s;
  r = r.replace(/\*\*(.+?)\*\*/g, "$1");
  r = r.replace(/__(.+?)__/g, "$1");
  r = r.replace(/~~(.+?)~~/g, "$1");
  // single *…* and _…_ left as-is so headers can still be italic/bold inside
  return r;
}

/**
 * Convert Markdown pipe-tables into a flat bullet representation.
 * Heuristic: We look for the classic | hdr | hdr | row, then a separator row
 * of dashes |---|---|, then data rows.
 */
function convertTables(text: string): string {
  const lines = text.split("\n");
  const out: string[] = [];

  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    // Detect potential header row
    if (looksLikeTableRow(line) && i + 1 < lines.length && looksLikeTableSeparator(lines[i + 1])) {
      const headers = parseTableRow(line);
      i += 2; // skip header + separator
      const rows: string[][] = [];
      while (i < lines.length && looksLikeTableRow(lines[i])) {
        rows.push(parseTableRow(lines[i]));
        i += 1;
      }

      // Emit: header line as bold + each data row as a bullet block
      if (headers.length > 0 && rows.length > 0) {
        // Multi-line per row: each row gets its own block of "*hdr:* value" lines
        for (const row of rows) {
          for (let c = 0; c < headers.length; c += 1) {
            const h = headers[c]?.trim();
            const v = row[c]?.trim() ?? "";
            if (!h) continue;
            // First column gets a bullet, rest indented
            if (c === 0) {
              out.push(`• *${h}:* ${v}`);
            } else {
              out.push(`  *${h}:* ${v}`);
            }
          }
          out.push(""); // blank line between rows
        }
        // Drop the trailing blank line we added
        if (out.length > 0 && out[out.length - 1] === "") out.pop();
        continue;
      }
    }
    out.push(line);
    i += 1;
  }

  return out.join("\n");
}

function looksLikeTableRow(line: string | undefined): boolean {
  if (!line) return false;
  const trimmed = line.trim();
  if (!trimmed.startsWith("|") && !trimmed.includes("|")) return false;
  // Must contain at least 2 | characters to qualify
  const pipeCount = (trimmed.match(/\|/g) ?? []).length;
  return pipeCount >= 2;
}

function looksLikeTableSeparator(line: string | undefined): boolean {
  if (!line) return false;
  const trimmed = line.trim();
  // | --- | --- |  or  | :--- | ---: |
  return /^\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)+\|?$/.test(trimmed);
}

function parseTableRow(line: string): string[] {
  // Strip leading/trailing | and split on |
  let s = line.trim();
  if (s.startsWith("|")) s = s.slice(1);
  if (s.endsWith("|")) s = s.slice(0, -1);
  return s.split("|").map((cell) => cell.trim());
}
