# Qyronex Kernal

[Dokumentation auf Deutsch](docs/de/README.md) · [Dissertationsartige technische Arbeit](docs/de/DISSERTATION_QYRONEX_KERNAL.md) · [English README](README.md)

**Qyronex Kernal** ist ein experimenteller, Capability-orientierter Hybrid-Kernel, der überwiegend in Rust entwickelt wird. Das Projekt wurde von **Moritz Wallinger** entworfen und gebaut.

Ziel ist ein kleiner privilegierter Kern mit expliziter Capability-basierter Rechtevergabe, geschützter Userspace-Ausführung, klaren Speicher- und Ownership-Grenzen sowie einer Linux-kompatiblen Userspace-ABI, ohne die interne Architektur des Linux-Kernels nachbauen zu müssen.

> **Status:** aktive Forschung und Entwicklung. Kernal ist nicht produktionsreif und darf derzeit nicht als produktive Sicherheitsgrenze eingesetzt werden.

![Qyronex-Kernal-Architektur](docs/assets/Architecture_comparison_diagram_…_38c24449_2K.jpg)

## Ziele

- Privilegierten und unsicheren Code möglichst klein und überprüfbar halten.
- Rechte explizit über Capabilities statt ausschließlich über implizite globale Autorität vergeben.
- Speicher-, Ausführungs-, Ownership- und Lebenszyklusgrenzen konsequent durchsetzen.
- Linux-Userspace-Kompatibilität über eine klar abgegrenzte Kompatibilitätsschicht bereitstellen.
- Architekturspezifische Mechanismen von architekturneutraler Policy trennen.
- Zentrale Runtime-Eigenschaften reproduzierbar in QEMU testen.

## Aktuelle Plattform

Der primäre Runtime-Pfad ist **AArch64 / ARM64**. Zusätzlich enthält der Quellbaum x86_64-Komponenten sowie gemeinsam genutzte, architekturneutrale Subsysteme.

Der aktuelle Quellbaum umfasst unter anderem:

- geschützte EL0-Userspace-Ausführung;
- AArch64-Exceptions, Syscalls, Kontextwechsel und Prozesspfade;
- virtuelle Speicherverwaltung und Adressräume;
- ELF-Loading und Linux-ARM64-ABI;
- Prozesse, Threads, Signale, Futexe und Lifecycle-Logik;
- Dateideskriptor-, Pipe- und VFS-Infrastruktur;
- Firmware-/Plattform-Parsing über FDT und ACPI;
- Capability- und Objektmodelle;
- sichere Speicherarchitektur;
- QEMU-basierte Integrations- und Kompatibilitätstests.

Die Linux-Kompatibilität zielt auf die **Userspace-ABI**. Linux-Kernelmodule sind kein Kompatibilitätsziel.

## Voraussetzungen

Das Workspace verwendet derzeit Rust **1.98.0**.

```bash
rustup toolchain install 1.98.0 --profile minimal --component rust-src,rustfmt,clippy,llvm-tools-preview
rustup target add --toolchain 1.98.0 aarch64-unknown-none-softfloat
```

Zusätzlich wird ein AArch64-fähiges QEMU benötigt.

## Bauen

```bash
cargo xtask arm-build
```

## In QEMU starten

```bash
cargo xtask arm-qemu
```

## Verifikation

```bash
bash tools/arm-first-verify.sh
```

Der öffentliche Prüfpfad umfasst Formatprüfung, Workspace-Tests, striktes Clippy, den AArch64-Build und den QEMU-Runtime-Test.

## Repository-Struktur

```text
.
├── abi/        Linux- und native ABI-Definitionen
├── boot/       Boot-, ELF-, Mapping-, UEFI- und Handoff-Code
├── drivers/    Treiberkomponenten
├── firmware/   ACPI/FDT und Plattform-Parsing
├── kernel/     Kernel-Subsysteme und Architektur-Backends
├── tests/      Integrations- und Kompatibilitätstests
├── tools/      Build-, Prüf- und Forschungswerkzeuge
├── xtask/      Rust-Build- und QEMU-Orchestrierung
└── docs/       technische Dokumentation
```

## Deutsche Dokumentation

Die zusätzliche deutschsprachige Dokumentation befindet sich unter [`docs/de/`](docs/de/). Dort sind Architektur, Boot, Speicherlayout, Roadmap, Debian-Kompatibilität und sichere Speicherarchitektur zusammengefasst.

Die ausführliche wissenschaftlich aufgebaute Projektarbeit befindet sich unter:

- [`docs/de/DISSERTATION_QYRONEX_KERNAL.md`](docs/de/DISSERTATION_QYRONEX_KERNAL.md)

## Sicherheitsprinzipien

- Unsicheren Rust-Code klein, lokal und mit `SAFETY:`-Begründung halten.
- Keine gleichzeitig schreibbaren und ausführbaren Speicherabbildungen.
- Seite 0 bleibt nach Übernahme der Seitentabellen ungemappt.
- User-Memory-Zugriffe sind begrenzt und explizit.
- Kernelobjekte sollen Capability-vermittelte Autorität verwenden.
- Nicht unterstützte Linux-Operationen müssen sichtbar fehlschlagen und dürfen keinen Erfolg vortäuschen.
- Kompatibilitätsarbeit darf zentrale Speicher-, Lifecycle-, DMA- oder Autoritätsinvarianten nicht schwächen.

Diese Punkte sind Architekturziele und Verträge. Sie stellen keine Behauptung dar, dass bereits ein vollständiges produktives Sicherheitsaudit abgeschlossen wurde.

## Autor

**Qyronex Kernal wurde von Moritz Wallinger entworfen und gebaut.**

Weitere Angaben befinden sich in [`AUTHORS.md`](AUTHORS.md).

## Lizenz

Qyronex Kernal steht unter der **Qyronex Kernal Nicht-Kommerziellen Lizenz 1.0**.

Nicht-kommerzielle private, schulische, akademische und entsprechend der Lizenz zulässige Forschungsnutzung ist erlaubt. **Kommerzielle Nutzung, produktive Unternehmensnutzung, Einbindung in bezahlte Produkte oder Dienste und andere gewerbliche Verwendung sind ohne separate schriftliche Lizenz untersagt.**

Der vollständige verbindliche Lizenztext befindet sich in [`LICENSE`](LICENSE).
