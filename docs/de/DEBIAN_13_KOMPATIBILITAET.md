# Debian-13-Kompatibilität

Qyronex Kernal verfolgt das Ziel, einen **unveränderten, klar eingegrenzten Debian-13-Userspace** auf der eigenen Kernelarchitektur auszuführen. Dabei soll die Linux-Userspace-ABI kompatibel genug werden, ohne die interne Linux-Kernelarchitektur zu kopieren.

## Grundsatz

Kompatibilität wird an beobachtbarem Verhalten gemessen:

- Rückgabewerte und `errno`;
- Signale und Prozessende;
- Datei- und Metadatenverhalten;
- Socket-/Netzwerkverhalten;
- stdout/stderr-Ausgaben, soweit deterministisch vergleichbar;
- erforderliche Syscalls, Ioctls, Pfade und Geräteinterfaces.

Nicht unterstützt bedeutet **explizites Scheitern**, typischerweise `ENOSYS` oder einen anderen korrekten Fehler. Ein Platzhalter, der Erfolg meldet, obwohl die Semantik fehlt, ist nicht zulässig.

## Gepinnte Referenz

Das Projekt verwendet für den ARM64-Referenzpfad ein festgelegtes Debian-13/Trixie-Cloud-Image und gepinnte Snapshot-Quellen. Images selbst werden nicht im Git-Repository gespeichert.

Vor Verwendung werden Größe und kryptographische Prüfsummen kontrolliert. Unversionierte `/latest/`-Quellen sind für den beweisorientierten Referenzpfad nicht zulässig.

## Entwicklungsreihenfolge

Die Kompatibilität wird abhängigkeitsorientiert aufgebaut:

1. statische und minimale Linux-Programme;
2. Prozess-/Thread-/Signal-/Futex-Grundlagen;
3. dynamischer Loader und glibc;
4. TTY/PTY;
5. persistentes Root-Dateisystem;
6. Netzwerk;
7. Event- und moderne Descriptor-APIs;
8. Namespaces/cgroups/Sicherheitscontracts;
9. `systemd` als unverändertes PID 1;
10. udev;
11. `dpkg` und `apt`;
12. reproduzierbarer Debian-Server-Proof.

## Keine Prozessnamen-Sonderfälle

Eine fehlende Linux-Semantik darf nicht dadurch kaschiert werden, dass der Kernel erkennt, ob ein bestimmtes Programm wie `systemd`, `apt` oder `dbus` läuft. Korrekturen gehören in die gemeinsame Linux-Kompatibilitätsschicht.

## Sicherheitsgrenze

Kompatibilität darf folgende Invarianten nicht aushebeln:

- W^X;
- Nullseiten-Schutz;
- Guard Pages;
- Capability-Autorität;
- Usercopy/PAN-Grenzen;
- DMA-/IOMMU-Isolation;
- Lifecycle- und Ownership-Regeln.

## Aussagegrenze

Erst wenn die jeweiligen Abnahmekriterien reproduzierbar erfüllt sind, darf eine konkrete Kompatibilitätsaussage gemacht werden. Das Projekt unterscheidet bewusst zwischen „implementiert“, „unverifiziert“, „teilweise“, „explizit nicht unterstützt“ und „nachgewiesen“.

Siehe [`../../DEBIAN_13_COMPATIBILITY_ROADMAP.md`](../../DEBIAN_13_COMPATIBILITY_ROADMAP.md).
