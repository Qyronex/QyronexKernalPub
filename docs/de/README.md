# Deutsche Dokumentation zu Qyronex Kernal

Diese Sammlung ergänzt die englische technische Dokumentation des Projekts. Sie richtet sich an deutschsprachige Entwickler, Reviewer und wissenschaftlich Interessierte.

**Autor und Hauptentwickler:** Moritz Wallinger

## Einstieg

- [`../../README_DE.md`](../../README_DE.md) – Projektübersicht, Build und Verifikation
- [`DISSERTATION_QYRONEX_KERNAL.md`](DISSERTATION_QYRONEX_KERNAL.md) – ausführliche wissenschaftliche Projektarbeit mit Linux-Vergleich
- [`BOOT_PROTOKOLL.md`](BOOT_PROTOKOLL.md) – Boot-Handoff und Speicherbesitz
- [`SPEICHERLAYOUT.md`](SPEICHERLAYOUT.md) – virtuelles Speicherlayout und harte Invarianten
- [`ROADMAP.md`](ROADMAP.md) – Entwicklungsphasen und Debian-Kompatibilitätsziel
- [`SICHERE_SPEICHERARCHITEKTUR.md`](SICHERE_SPEICHERARCHITEKTUR.md) – Capability-basierte sichere Persistenz
- [`DEBIAN_13_KOMPATIBILITAET.md`](DEBIAN_13_KOMPATIBILITAET.md) – Strategie für unveränderten Debian-13-Userspace
- [`DEBIAN_13_ORAKEL.md`](DEBIAN_13_ORAKEL.md) – Referenzmessung und Vergleich gegen Debian/Linux

## Verhältnis zur englischen Dokumentation

Die deutschsprachigen Dokumente erklären die zentralen Architekturverträge und die Entwicklungsstrategie. Maschinenlesbare JSON-Manifeste, Test-Fixtures und einzelne schrittbezogene Arbeitsmanifeste bleiben in ihrer ursprünglichen Form erhalten, da sie gleichzeitig Eingabe für automatisierte Prüfungen sind.

Bei einem Widerspruch zwischen einer erklärenden Übersetzung und einem maschinenlesbaren Test-/ABI-Vertrag ist der tatsächlich getestete Quellcode beziehungsweise der maschinenlesbare Vertrag maßgeblich.

## Lizenz

Die Dokumentation ist Bestandteil von Qyronex Kernal und unterliegt der [`Qyronex Kernal Nicht-Kommerziellen Lizenz 1.0`](../../LICENSE). Kommerzielle Nutzung erfordert eine separate schriftliche Lizenz.
