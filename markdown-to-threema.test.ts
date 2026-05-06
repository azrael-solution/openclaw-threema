/**
 * markdown-to-threema.test.ts
 * Run via: tsx markdown-to-threema.test.ts
 *          (or compile + node)
 */
import { markdownToThreema } from "./markdown-to-threema.ts";

interface Case {
  name: string;
  input: string;
  expected: string;
}

const cases: Case[] = [
  {
    name: "empty",
    input: "",
    expected: "",
  },
  {
    name: "plain text passes through",
    input: "Hallo aza!",
    expected: "Hallo aza!",
  },
  {
    name: "**bold** → *bold*",
    input: "Das ist **fett**.",
    expected: "Das ist *fett*.",
  },
  {
    name: "__bold__ → *bold*",
    input: "Das ist __fett__.",
    expected: "Das ist *fett*.",
  },
  {
    name: "single *italic* stays as-is (will render as bold in Threema)",
    input: "Das ist *kursiv*.",
    expected: "Das ist *kursiv*.",
  },
  {
    name: "_italic_ stays as-is",
    input: "Das ist _kursiv_.",
    expected: "Das ist _kursiv_.",
  },
  {
    name: "~~strike~~ → ~strike~",
    input: "Das ist ~~weg~~.",
    expected: "Das ist ~weg~.",
  },
  {
    name: "# header → *header*",
    input: "# Mein Titel",
    expected: "*Mein Titel*",
  },
  {
    name: "## H2 → *H2*",
    input: "## Untertitel",
    expected: "*Untertitel*",
  },
  {
    name: "header with **inline bold** strips markers",
    input: "## **Wichtig**",
    expected: "*Wichtig*",
  },
  {
    name: "horizontal rule → unicode line",
    input: "Above\n---\nBelow",
    expected: "Above\n─────────────\nBelow",
  },
  {
    name: "unordered list with -",
    input: "- Eins\n- Zwei\n- Drei",
    expected: "• Eins\n• Zwei\n• Drei",
  },
  {
    name: "unordered list with *",
    input: "* Eins\n* Zwei",
    expected: "• Eins\n• Zwei",
  },
  {
    name: "nested list keeps indent",
    input: "- Top\n  - Sub\n  - Sub2",
    expected: "• Top\n  • Sub\n  • Sub2",
  },
  {
    name: "blockquote → vertical bar",
    input: "> wichtig\n> noch wichtig",
    expected: "│ wichtig\n│ noch wichtig",
  },
  {
    name: "inline code → quoted",
    input: "Run `npm install` first.",
    expected: 'Run "npm install" first.',
  },
  {
    name: "fenced code block keeps content, drops fences",
    input: "Vor\n```bash\nls -la\necho hi\n```\nNach",
    expected: "Vor\nls -la\necho hi\nNach",
  },
  {
    name: "[link](url) → label — url",
    input: "Siehe [Docs](https://example.com).",
    expected: "Siehe Docs — https://example.com.",
  },
  {
    name: "[url](url) → just url",
    input: "Siehe [https://example.com](https://example.com).",
    expected: "Siehe https://example.com.",
  },
  {
    name: "![alt](url) → [Bild: alt] — url",
    input: "![Logo](https://x.com/logo.png)",
    expected: "[Bild: Logo] — https://x.com/logo.png",
  },
  {
    name: "table → bullet rows with bold headers",
    input: "| Name | Alter |\n|---|---|\n| aza | 56 |\n| FG | n/a |",
    expected:
      "• *Name:* aza\n  *Alter:* 56\n\n• *Name:* FG\n  *Alter:* n/a",
  },
  {
    name: "consecutive blank lines collapse",
    input: "Eins\n\n\n\nZwei",
    expected: "Eins\n\nZwei",
  },
  {
    name: "complex realistic FireGolem reply",
    input: [
      "## ✅ Wartung 06.05. 05:00 — alle 4 Boxen grün",
      "",
      "| Box | Kernel |",
      "|---|---|",
      "| Mephisto | 6.8.0-111 |",
      "| Caldera | 6.8.0-110 |",
      "",
      "**Lessons:**",
      "- Bei OC-Major-Upgrade immer `doctor --fix`",
      "- Mesh: `compose down && up -d` präventiv",
      "",
      "[Mehr Infos](https://docs.openclaw.ai)",
    ].join("\n"),
    expected: [
      "*✅ Wartung 06.05. 05:00 — alle 4 Boxen grün*",
      "",
      "• *Box:* Mephisto",
      "  *Kernel:* 6.8.0-111",
      "",
      "• *Box:* Caldera",
      "  *Kernel:* 6.8.0-110",
      "",
      "*Lessons:*",
      '• Bei OC-Major-Upgrade immer "doctor --fix"',
      '• Mesh: "compose down && up -d" präventiv',
      "",
      "Mehr Infos — https://docs.openclaw.ai",
    ].join("\n"),
  },
];

let pass = 0;
let fail = 0;
for (const c of cases) {
  const got = markdownToThreema(c.input);
  if (got === c.expected) {
    pass += 1;
    console.log(`  ✓ ${c.name}`);
  } else {
    fail += 1;
    console.log(`  ✗ ${c.name}`);
    console.log(`    input:    ${JSON.stringify(c.input)}`);
    console.log(`    expected: ${JSON.stringify(c.expected)}`);
    console.log(`    got:      ${JSON.stringify(got)}`);
  }
}

console.log(`\n${pass}/${pass + fail} passing`);
if (fail > 0) {
  process.exit(1);
}
