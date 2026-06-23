# Threema Gateway — Reactions API Verification (2026-06-24)

_Sprint #1b: "Reactions verifizieren+evtl. bauen". Hard rule: ZUERST verifizieren ob die Threema-Gateway-API Reactions überhaupt kann — nicht raten._

## Verdict: ❌ API-limitiert — arbitrary Emoji-Reactions NICHT über das Threema Gateway möglich

`capabilities.reactions` bleibt **`false`** (korrekt). Keine Code-Änderung.

## Evidenz (offizielle Quellen, nicht geraten)

Maßgeblich ist die **E2E-Container-Spec der Threema-Gateway-Doku**
(https://gateway.threema.ch/en/developer/e2e, abgerufen 2026-06-24). Sie listet
**abschließend** die vom Gateway unterstützten E2E-Message-Typen (`type`-Byte):

| type | Bedeutung |
|------|-----------|
| 0x01 | text |
| 0x17 | file |
| 0x10 | location |
| 0x80 | delivery-receipt |
| 0x15 | poll-setup |
| 0x16 | poll-vote |

**Es gibt KEINEN `reaction`-Message-Typ in der Gateway-Container-Spec.**

Das moderne "Emoji-Reactions"-Feature der vollen Threema-Apps (Blog:
https://threema.com/en/blog/emoji-reactions) nutzt im Clients-Protokoll einen
eigenen `reaction`-E2E-Typ mit beliebigem Emoji. Dieser Typ ist über die
**Gateway-API nicht exponiert** — Gateway-IDs sind ein eingeschränktes Subset.
Reddit-Bestätigung aus der Praxis: bei Gateway/eingeschränkten Kontexten
erscheint nur das alte "Agree/Disagree", nicht der volle Emoji-Picker.

## Einzige reaction-ähnliche Primitive im Gateway: delivery-receipt ack/decline

`delivery-receipt` (0x80) trägt ein `status`-Byte:

- 0x01 received
- 0x02 read
- **0x03 acknowledged (👍 "Agree")**
- **0x04 declined (👎 "Disagree")**

Das ist die **Legacy "Agree/Disagree"**-Funktion — nur Daumen hoch / runter auf
eine konkrete Message-ID, **kein** beliebiges Emoji. Inbound decodieren wir
bereits (index.ts ~2980, status 3 = "acknowledged").

### Was theoretisch baubar wäre (eigene Entscheidung, NICHT autonom gebaut)

Ein Outbound-`acknowledge`/`decline` (0x03/0x04) auf die zuletzt empfangene
Message-ID. Das gäbe ein 👍/👎-Ack ohne Voll-Nachricht — aber:

- nur 2 feste Reaktionen (👍/👎), kein "React Like a Human" mit passendem Emoji,
- semantisch aufgeladen ("Disagree" wirkt schnell schroff),
- braucht Tracking der letzten Inbound-Message-ID pro Chat im Outbound-Pfad.

→ Das ist ein **anderes, dünneres Feature** als "Reactions" wie in der Roadmap
gemeint. Deshalb hier NICHT autonom gebaut, sondern aza zur Entscheidung
vorgelegt. Per Sprint-Regel ("ein Punkt pro Nacht, bei API-Limit nächsten Punkt
nicht automatisch mitmachen") wird #2 Reply nicht angefasst.

## Empfehlung

1. `reactions` bleibt `false`. Roadmap-Punkt #1 als **API-limitiert** schließen.
2. Optional-Ticket für aza: "👍/👎-Ack via delivery-receipt 0x03/0x04" — nur wenn
   er das dünne Primitive will. Sonst ersatzlos.
3. Nächster Sprint-Punkt regulär: #2 Reply/Quote (Do 25.06.) — separat verifizieren
   (Quote-Reply braucht im Clients-Protokoll ebenfalls eigenen Typ; vorab prüfen
   ob Gateway das kann, gleiche Methodik wie hier).
