# Entwicklungsroadmap von Qyronex Kernal

Die Roadmap beschreibt die Entwicklung von einem minimal bootfähigen Kernel zu einem System, das einen abgegrenzten, unveränderten Debian-13-Userspace ausführen kann.

## Phase M0 – Fundament

- reproduzierbarer Build;
- UEFI-/QEMU-Boot;
- serieller Diagnosepfad;
- definierter QEMU-Exit.

## Phase M1 – Boot und Speicherbesitz

- geprüfter ELF64-Loader;
- versionierter BootInfo-Handoff;
- `ExitBootServices`-Übergang;
- kernel-eigene Seitentabellen;
- W^X-konforme RX/R/RW-Mappings;
- Exception-Reporting;
- physischer Frame-Besitz;
- Guard Pages.

## Phase M2 – SMP, Capabilities und IPC

- Multiprozessorstart;
- per-CPU-Zustand und Runqueues;
- präemptiver Scheduler;
- skalierbares Capability-/Objektmodell;
- IPC-Endpunkte und Notifications;
- negative Autorisierungstests.

## Phase M3 – Userspace und Linux-Bootstrap

- geschützte Useradressräume;
- User-ELF-Loader;
- native Capability-ABI;
- Linux-Syscall-Einstieg;
- erste unveränderte Linux-Programme.

## Phase M4 – Geräteisolation

- PCIe-Erkennung;
- Interruptvermittlung;
- IOMMU/SMMUv3-Modelle;
- VirtIO-/spätere Geräteservices;
- negative DMA-Tests.

## Phase M5 – Server-Nutzbarkeit

- VFS und persistenter Storage;
- Netzwerk;
- Futexe, Signale, Sockets und Event-APIs;
- dynamisches ELF/glibc;
- wachsende Debian-Workloads.

## Debian-13-Pfad

Der weiterführende Kompatibilitätspfad ist bewusst schrittweise aufgebaut:

- dynamische glibc-Programme;
- TTY/PTY und Job-Control;
- persistentes Root-Dateisystem und Mountmodell;
- Netzwerk und Resolver;
- moderne Event-/Descriptor-APIs;
- Namespaces, cgroups v2 und sicherheitsnahe Linux-Contracts;
- unverändertes `systemd` als PID 1;
- udev und Device Model;
- `dpkg`/`apt` mit Haltbarkeitssemantik;
- reproduzierbarer Debian-13-Server-Rootfs-Proof;
- optionale Container- und Hardwareerweiterung;
- abschließende Kompatibilitäts- und Stresstests.

## Beweisanforderung

Ein implementierter Codepfad allein gilt nicht als Beweis. Für zentrale Kompatibilitätsaussagen werden ausführbare Tests, referenzierte Debian-Ergebnisse und reproduzierbare QEMU-Läufe benötigt.

## Nicht-Ziele

- vollständige Binär- oder Treiberkompatibilität mit Linux-Kernelmodulen;
- Behauptung vollständiger Linux-Kompatibilität ohne getestete Evidenz;
- Prozessnamen-spezifische Sonderpfade für Debian-Komponenten;
- Aufweichen der Capability-, W^X-, Ownership- oder DMA-Regeln zugunsten kurzfristiger Kompatibilität.

Die englische Detailroadmap befindet sich in [`../../DEBIAN_13_COMPATIBILITY_ROADMAP.md`](../../DEBIAN_13_COMPATIBILITY_ROADMAP.md).
