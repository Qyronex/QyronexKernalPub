# Debian-13-Referenzorakel

Das Referenzorakel ist die Messmethodik, mit der Qyronex Kernal Linux-/Debian-Verhalten nicht aus Annahmen, sondern aus reproduzierbaren Referenzläufen ableitet.

## Ziel

Ein identischer, begrenzter Testfall wird in einer verifizierten Debian-13-ARM64-Referenzumgebung ausgeführt. Die beobachtbaren Resultate werden strukturiert erfasst und anschließend mit dem Verhalten von Qyronex Kernal verglichen.

## Referenzzustände

Die Kompatibilitätsmatrix unterscheidet:

- `SUPPORTED_PROVEN` – ausführbare Evidenz für den konkreten Vertrag vorhanden;
- `SUPPORTED_UNVERIFIED` – Implementierung vorhanden, aber Referenzbeweis fehlt;
- `PARTIAL` – nur Teilmenge umgesetzt oder bewiesen;
- `ENOSYS_UNSUPPORTED` – explizit nicht unterstützt;
- `NOT_REQUIRED` – für den festgelegten Zielkorpus nachweislich nicht erforderlich.

Unbekannte Operationen sollen nicht optimistisch als erfolgreich behandelt werden.

## Provenienz

Jeder belastbare Referenzlauf bindet die Ergebnisse an:

- exakten Source-Commit;
- exakte Debian-Image-Identität;
- Imagegröße und Hashes;
- definierte Probe-/Schema-Version;
- die konkrete Referenzumgebung.

Damit kann eine spätere Code- oder Schemaänderung nicht still alte Evidenz als Beweis für einen neuen Zustand verwenden.

## Vergleich

Verglichen werden unter anderem Rückgabewerte, `errno`, Signale, Exit-Status, Hashes deterministischer Ausgaben, Metadaten und Socketverhalten.

Der Comparator soll Unterschiede sichtbar machen und nicht automatisch tolerieren. Ein bekannter Gap bleibt ein Gap, bis Implementierung und Referenzsemantik übereinstimmen oder die Abweichung ausdrücklich dokumentiert ist.

## Wissenschaftlicher Nutzen

Diese Methodik trennt drei Ebenen:

1. **Behauptung:** ein Linux-Vertrag soll unterstützt werden;
2. **Implementierung:** Code für den Vertrag existiert;
3. **Evidenz:** der konkrete Vertrag wurde gegen eine gepinnte Referenz ausgeführt und verglichen.

Diese Trennung ist für ein Forschungsbetriebssystem besonders wertvoll, weil sie verhindert, dass Quellcodeumfang mit tatsächlicher Kompatibilität gleichgesetzt wird.

Die detaillierte englische Beschreibung befindet sich in [`../debian13/README.md`](../debian13/README.md).
