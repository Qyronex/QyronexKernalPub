# Sichere Speicherarchitektur

Qyronex Kernal betrachtet Persistenz nicht nur als Dateisystemproblem. Ziel ist eine Capability-gesicherte, verschlüsselte, integritätsgeschützte und für asynchronen I/O geeignete Speicherarchitektur.

## Sicherheitsziel

Die Kompromittierung eines einzelnen Prozesses, Mandanten, Treibers oder Namespaces soll nicht automatisch Zugriff auf unabhängige persistente Daten ermöglichen.

Zentrale Anforderungen:

- explizite Capability-vermittelte Speicherautorität;
- Verschlüsselung geschützter Daten im Ruhezustand;
- kryptographische Integrität für Daten und sicherheitsrelevante Metadaten;
- hierarchische Schlüsseltrennung;
- hardwaregestützter Root-of-Trust, soweit verfügbar;
- IOMMU/SMMUv3-gestützte DMA-Begrenzung;
- asynchrone, bounded Queue-basierte I/O-Pfade;
- fail-closed Verhalten bei Autoritäts-, Integritäts-, Schlüssel- oder Ownership-Fehlern.

## Autoritätsmodell

Ein Pfadname allein ist keine ausreichende Autorität. Ein Prozess oder Service erhält Zugriff auf persistente Objekte über explizit delegierte Capabilities. Eine Capability kann beispielsweise ein Gerät, Volume, einen Mandanten, Namespace, ein Objekt, einen Extent oder eine Queue repräsentieren.

Linux-kompatible Pfad- und Dateideskriptorsemantik darf im Userspace angeboten werden, soll intern jedoch auf das kanonische Capability-Modell abgebildet werden.

## Schlüsselhierarchie

Das Zielmodell lautet konzeptionell:

`Hardware-/Root-Key -> System-Key -> Mandanten-/Namespace-Key -> Volume-Key -> Objekt-/Extent-Key`

Die Ebenen dürfen technisch zusammengefasst werden, wenn die Sicherheitsargumentation erhalten bleibt. Ein kompromittierter Volume- oder Mandantenschlüssel soll nicht automatisch unabhängige Volumes beziehungsweise Mandanten offenlegen.

Root-Schlüssel dürfen nicht im Klartext persistent gespeichert werden. Schlüsselmaterial im RAM benötigt explizite Ownership und Lebensdauer und darf nicht in normalen Logs oder unspezifischen IPC-Payloads erscheinen.

## Authentifizierte Speicherung

Verschlüsselung ohne Manipulationserkennung reicht nicht. Geschützte Daten und sicherheitskritische Metadaten müssen authentifiziert sein. Änderungen, Substitutionen oder unzulässige Rollbacks dürfen nicht still akzeptiert werden.

Erforderlich sind unter anderem:

- AEAD oder äquivalent begründete Konstruktionen;
- generationengebundene Nonces/Counters;
- authentifizierte Metadatenwurzeln beziehungsweise Bäume;
- definierte Replay-/Rollback-Regeln;
- deterministisches Versagen bei falschen oder fehlenden Schlüsseln.

## DMA- und Treiberisolation

Speichergeräte erhalten keine pauschale physische Speicherautorität. DMA-Mappings müssen explizit, begrenzt, Capability-gebunden und vor Wiederverwendung von Frames widerrufen werden.

Ein kompromittierter Storage-Treiber darf nicht allein durch Kontrolle einer Gerätequeue Zugriff auf Kernel-Schlüssel oder fremde Mandantenpuffer erlangen.

## Datenpfad

Zu vermeiden ist eine starre Kopierkette wie:

`Anwendung -> Kernelkopie -> Kryptokopie -> Treiberkopie -> Gerät`

Das Ziel ist ein kontrollierter Pfad:

`autorisierter Puffer -> Storage-Queue -> Kryptographie/Authentisierung -> begrenztes DMA-Mapping -> Gerät`

Zero-/Low-Copy ist nur zulässig, wenn Mutabilität, Lebensdauer, Capability-Autorität, Schlüsselgrenzen und DMA-Besitz eindeutig bleiben.

## Asynchrones I/O

Der kanonische Storage-Pfad soll Queue-orientiert sein. Anforderungen sind:

- begrenzte Queuegrößen und In-Flight-Operationen;
- Backpressure statt unbegrenzter Allokation;
- generationensichere Request-IDs;
- saubere Cancellation-/Teardown-Semantik;
- Sharding oder per-CPU/per-Service-Queues, wo sinnvoll;
- Batching zur Reduktion von Syscall-, Crypto- und Doorbell-Kosten.

Linux-`read`/`write` kann als synchrone Fassade darüber implementiert werden.

## Schichtenmodell

```text
Anwendung / Datenbank
        |
Storage-Capability
        |
Namespace-/Storage-Service
        |
verschlüsselte + authentifizierte Objekte/Extents
        |
Key-Service / Hardware-Root
        |
asynchrones Block-I/O
        |
isolierter VirtIO-/NVMe-Transport
        |
IOMMU-begrenztes DMA
        |
Speichergerät
```

## Abnahmephilosophie

Quellcode allein ist kein Sicherheitsbeweis. Für die Abnahme sind mindestens negative Autorisierungstests, Manipulationstests, Wrong-Key/Missing-Key-Tests, Crash-/Torn-Write-Tests und – wo Hardware verfügbar ist – DMA-Isolationsnachweise erforderlich.

Die ausführliche englische Architektur ist in [`../../SECURE_STORAGE_ARCHITECTURE.md`](../../SECURE_STORAGE_ARCHITECTURE.md) dokumentiert.
