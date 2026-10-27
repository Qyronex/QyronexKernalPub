# Virtuelles Speicherlayout und Speicherinvarianten

Qyronex Kernal trennt User- und Kerneladressräume strikt und behandelt Speicherschutz nicht als nachträgliche Härtung, sondern als Architekturvertrag.

## Grundmodell

Für x86_64 liegt der Userspace im unteren kanonischen Adressbereich, während das Kernelimage in der oberen Hälfte liegt. Für AArch64 gelten architekturspezifische Seitentabellen- und EL0/EL1-Regeln; die übergeordneten Sicherheitsinvarianten bleiben jedoch gleich.

## Harte Invarianten

1. **W^X:** Kernelcode darf nicht gleichzeitig schreibbar und ausführbar abgebildet sein.
2. **Nullseite:** Seite 0 bleibt nach Installation kernel-eigener Tabellen ungemappt.
3. **Guard Pages:** Kernel- und sensible Thread-Stacks erhalten ungemappte Schutzbereiche.
4. **Userspace-Markierung:** User-Mappings müssen als Userzugriff gekennzeichnet sein und dürfen keinen schreibbaren Alias auf Kerneltext erzeugen.
5. **MMIO:** Gerätespeicher wird nicht ausführbar gemappt und verwendet geeignete Cacheattribute.
6. **Expliziter Usercopy:** Der Kernel greift nicht beliebig auf Userspace-Pointer zu; Kopierpfade müssen Grenzen und Zugriffsrichtung prüfen.

## Beispiel des frühen x86_64-Vertrags

| Bereich | Frühe Basis | Richtlinie |
| --- | ---: | --- |
| Userspace | `0x0000000000000000` | Ring 3, standardmäßig NX |
| Kernelimage | `0xffffffff80200000` | getrennte ELF-`PT_LOAD`-Segmente |
| Kerneltext | linkerdefiniert | R-X |
| Kernel-Rodata | linkerdefiniert | R--, NX |
| Kernel-Daten/BSS | linkerdefiniert | RW-, NX |

Die Zahlenwerte sind ein Entwicklungsvertrag und keine Garantie, dass spätere Layouts identisch bleiben. KASLR, Direct Maps, per-CPU-Bereiche oder MMIO-Fenster können das konkrete Layout verändern, ohne die Sicherheitsinvarianten aufzugeben.

## Vergleich mit klassischem Linux

Linux besitzt eine sehr umfassende virtuelle Speicherverwaltung mit Demand Paging, Page Cache, NUMA-Policy, Huge Pages, Reclaim, Swap und vielen Spezialpfaden. Qyronex Kernal ist funktional deutlich weniger reif, legt aber von Beginn an Wert darauf, W^X, Nullseiten-Schutz, Guard Pages und explizite Ownership als feste Bedingungen zu behandeln.

Siehe auch [`../MEMORY_LAYOUT.md`](../MEMORY_LAYOUT.md).
