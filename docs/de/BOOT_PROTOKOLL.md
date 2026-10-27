# Boot-Protokoll von Qyronex Kernal

Das Boot-Protokoll definiert die Grenze zwischen Firmware/Loader und dem privilegierten Kernel. Der zentrale Grundsatz lautet: **Firmware-interne Strukturen werden nicht ungeprüft in den Kernel übernommen.** Stattdessen erfolgt der Übergang über eine versionierte, explizite ABI.

## Versionierter Handoff

Der UEFI-Loader und der Kernel kommunizieren über die `kernal-bootinfo`-ABI. Die Struktur enthält nur Daten, deren Layout, Größe und Bedeutung für die jeweilige Version festgelegt sind.

Ziele:

- reproduzierbarer Übergang von Firmware zu Kernel;
- keine implizite Abhängigkeit des Kernels von UEFI-internen Datenstrukturen;
- validierbare Größen, Adressen und Bereichsgrenzen;
- spätere kompatible Erweiterung durch Versionierung.

## Speicherkarte

`BootInfoV1.memory_map` beschreibt eine zusammenhängende Folge normalisierter Speicherregionen. Größe und Anzahl der Einträge werden explizit übertragen.

Vor der Übergabe muss der Loader die UEFI-Speicherkarte normalisieren. Unbekannte Firmwaretypen werden konservativ als reserviert eingestuft. Runtime-Firmware-Speicher darf nicht automatisch dem physischen Frame-Allocator als frei zur Verfügung gestellt werden.

Der Kernel prüft jede Region mindestens auf:

1. Länge größer als null;
2. Überlauf bei `Startadresse + Länge`;
3. gültige Klassifikation;
4. Nichtüberschneidung mit weiterhin geschützten Bereichen.

Nur ausdrücklich als nutzbar klassifizierter Speicher darf in die frühe physische Speicherverwaltung eingehen.

## Eigentumsübergang

Vor `ExitBootServices` besitzt die Firmware Boot-Service-Ressourcen. Nach erfolgreichem `ExitBootServices` wird die normalisierte Speicherkarte eingefroren und an den Kernel übergeben.

Ein Bereich, der theoretisch zurückgewinnbar ist, wird nicht allein deshalb automatisch frei. Das zuständige Subsystem muss seinen Besitz explizit aufgeben. Dieses Modell verhindert, dass Speicher gleichzeitig von zwei Komponenten als exklusiv nutzbar betrachtet wird.

## Sicherheitsinvarianten

- Keine Nutzung ungeprüfter Firmware-Pointer nach dem Handoff.
- Kein implizites Freigeben von Runtime-Firmware-Speicher.
- Keine stillen Ganzzahlüberläufe in Adress- oder Längenberechnungen.
- Keine Annahme, dass unbekannte Firmwaretypen sicher nutzbar sind.
- Frühestmöglicher Übergang zu kernel-eigenen Seitentabellen und Ownership-Regeln.

## Abgrenzung zu Linux

Linux unterstützt zahlreiche Bootpfade und Plattformvarianten und enthält umfangreiche, historisch gewachsene Firmwareintegration. Qyronex Kernal verfolgt für den aktuellen Forschungsstand einen engeren Vertrag: Daten werden vor dem Übergang normalisiert und der Kernel soll möglichst wenig Firmwarezustand als implizite Autorität übernehmen.

Siehe auch die englische Fassung [`../BOOT_PROTOCOL.md`](../BOOT_PROTOCOL.md).
