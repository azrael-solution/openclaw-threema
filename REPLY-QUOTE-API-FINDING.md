# Threema Gateway — Reply/Quote API Verification (2026-06-25)

_Sprint #2: "Reply/Quote — `reply: false` → true". Hard rule: ZUERST verifizieren ob die
Threema-Gateway-API Quote-Replies überhaupt kann — nicht raten (SOUL.md)._

## Verdict: ❌ API-limitiert — native Quote-Replies sind über das Threema **Gateway** nicht sauber möglich

`capabilities.reply` bleibt **`false`** (korrekt). Keine Code-Änderung.

## Evidenz (offizielle Quellen, live abgerufen 2026-06-25, nicht geraten)

### 1. Gateway-Send-Endpoints haben KEINEN Quote-/Reply-Parameter

Offizielle Gateway-API-Doku (https://gateway.threema.ch/en/developer/api):

- `POST /send_simple` — Parameter: `from`, `to`/`phone`/`email`, **`text`**, `secret`. Sonst nichts.
- `POST /send_e2e` — Parameter: `from`, `to`, `nonce`, **`box`** (verschlüsselter Container),
  `secret`, optional `noDeliveryReceipts`/`noPush`/`group`.
- `POST /send_e2e_bulk` — wie send_e2e, JSON-Array.

**Es existiert kein `quote`-, `replyTo`-, `inReplyTo`- oder Message-Referenz-Parameter**
in irgendeinem Send-Endpoint. Man kann ausschließlich freien Text (bzw. den E2E-Box-Container)
senden.

### 2. E2E-Container-Spec hat keinen Quote-Message-Typ

Die abschließende Liste der vom Gateway unterstützten E2E-Container-Typen (vgl.
`REACTIONS-API-FINDING.md`, geprüft 2026-06-24):
`0x01 text`, `0x17 file`, `0x10 location`, `0x80 delivery-receipt`, `0x15 poll-setup`,
`0x16 poll-vote`. **Kein Quote-/Reply-Typ.** Ein Quote ist also auch im E2E-Box-Container
nicht als eigenständige Struktur transportierbar.

### 3. Das strukturierte Quote-Modell gehört zum App-Remote-Protokoll, NICHT zum Gateway

Threema hat ein strukturiertes `Quote`-Modell mit Feldern
`identity` / `text` / `messageId` (https://threema-ch.github.io/app-remote-protocol/model-quote.html).
Dieses Modell ist Teil des **App-Remote-Protokolls** (Threema Web / Desktop ↔ App), ein
**komplett anderes Protokoll** als die Gateway-HTTP-API. Über das Gateway ist es nicht exponiert.

### 4. OpenClaw-Seite: `replyToId` ist nur ein generisches Interface-Feld

`index.ts` definiert `ChannelOutboundContext.replyToId?: string | null` (Zeile 64) — das ist
die **generische OpenClaw-Outbound-Shape**, nicht Threema-spezifisch. Im gesamten Plugin-Code
wird `replyToId` **nirgends verwendet** (einzige Fundstelle = die Interface-Deklaration). Es gibt
also nichts, woran ein Quote-Reply andocken könnte, weil die Gateway-API das Ziel nicht annimmt.

## Caveat: Legacy-Text-Quote-Syntax (bewusst NICHT gebaut)

Ältere Threema-Apps parsen eine **Legacy-Quote-Syntax direkt im Text-Body**:

```
> quote #<8-byte-hex-messageId>

<eigentlicher Antworttext>
```

Da das reiner Text ist, *könnte* das Gateway es technisch übertragen (es ist ja nur ein
`text`-Container). ABER:

- **Brüchig & versionsabhängig:** wird nur gerendert, wenn die Empfänger-App diese Syntax noch
  parst. Tut sie es nicht (neuere Clients bevorzugen das strukturierte Quote-Modell), erscheint
  beim Empfänger wörtlich `> quote #abcdef12` als Text-Müll.
- **Message-ID-Tracking nötig:** wir müssten die 8-Byte-Hex-Message-ID jeder zu zitierenden
  Inbound-Nachricht pro Chat im Outbound-Pfad mitführen. Das Inbound decodieren wir zwar, aber
  ein sauberes Mapping „Agent will DIESE Nachricht quoten" gibt es im OpenClaw-Reply-Flow nicht.
- **Nicht das, was `reply: true` verspricht:** ein echtes natives Quote (anklickbar, springt zur
  Originalnachricht) ist es NICHT — nur formatierter Text, der bei manchen Clients hübsch aussieht.

→ Das wäre ein **dünnes, fragiles Pseudo-Feature**, kein verlässliches `reply: true`. Per
SOUL-Regel („eine falsche Information / ein wackliges Feature ist schlimmer als gar keins")
und Sprint-Regel (bei API-Limit nicht autonom basteln) **NICHT gebaut**, sondern aza vorgelegt.

## Empfehlung

- `capabilities.reply` bleibt `false` — ehrlich und korrekt.
- Falls aza das Legacy-Text-Quote dennoch als „nice to have" will: eigener Slot, klar als
  Best-Effort-Kosmetik gelabelt, mit Inbound-Message-ID-Tracking. Kein Sprint-Autonom-Task.
- Per Sprint-Regel „ein Punkt pro Nacht, bei API-Limit nächsten nicht automatisch" wird
  **#4 Typing-Indicator NICHT in derselben Nacht angefasst**.

---
_Geprüft & verfasst von FireGolem, 2026-06-25 ~01:30. Quellen live abgerufen, nicht aus dem Gedächtnis._
