# Entwurf und Evaluation einer Capability-orientierten Hybridkernel-Architektur mit Linux-Userspace-Kompatibilität

## Dissertationsartige technische Projektarbeit zu Qyronex Kernal

**Autor und Entwickler des untersuchten Systems:** Moritz Wallinger  
**Projekt:** Qyronex Kernal  
**Stand:** 2026  

> **Hinweis zur Einordnung:** Dieses Dokument ist eine wissenschaftlich strukturierte technische Projektarbeit im Stil einer Dissertation. Es ist keine Aussage darüber, dass diese Fassung von einer Hochschule als Dissertation angenommen wurde oder dass daraus ein akademischer Grad abgeleitet werden kann.

---

## Zusammenfassung

Diese Arbeit untersucht den Entwurf von Qyronex Kernal, einem überwiegend in Rust implementierten, Capability-orientierten Hybridkernel. Das Projekt verfolgt das Ziel, drei Anforderungen miteinander zu verbinden, die in Betriebssystemen häufig in Spannung stehen: eine möglichst explizite und überprüfbare Autoritätsstruktur, eine moderne speichersicherheitsorientierte Implementierung sowie eine hinreichende Linux-Userspace-ABI-Kompatibilität, damit bestehende Programme und langfristig ein eingegrenzter Debian-13-Userspace unverändert ausgeführt werden können.

Als Referenz dient der klassische Linux-Kernel im Sinne der etablierten monolithischen, modular erweiterbaren Linux-Architektur. Linux ist ein ausgereiftes General-Purpose-Betriebssystem mit einer außerordentlich breiten Hardware-, Dateisystem-, Netzwerk- und Userspace-Unterstützung. Qyronex Kernal ist demgegenüber ein Forschungs- und Entwicklungsprojekt. Die Arbeit behauptet daher keine Gleichwertigkeit hinsichtlich Reife, Performance, Treiberabdeckung oder Sicherheitszertifizierung. Untersucht wird vielmehr, welche architektonischen Unterschiede entstehen, wenn Linux-Userspace-Kompatibilität nicht durch Übernahme der internen Linux-Struktur, sondern durch eine explizite Kompatibilitätsschicht über einem Capability-orientierten Kern realisiert werden soll.

Die Analyse zeigt, dass die Trennung von interner Autorität und externer Linux-ABI ein tragfähiges Forschungsmodell ist: Linux-Semantik kann an der Systemaufrufgrenze nachgebildet werden, während interne Objekte andere Autorisierungs- und Ownership-Regeln verwenden. Gleichzeitig verschiebt dieser Ansatz Komplexität in Übersetzungs-, Lebenszyklus- und Kompatibilitätsschichten. Besonders kritisch sind Prozesse und Threads, Signale, Futexe, VFS-Semantik, dynamisches ELF/glibc, Event-APIs, Namespaces, cgroups und die Gerätewelt von systemd/udev.

---

## 1. Einleitung

Der Linux-Kernel ist die Grundlage einer großen Zahl von Server-, Desktop-, Embedded- und Cloud-Systemen. Seine praktische Stärke liegt in jahrzehntelanger Evolution, breiter Hardwareunterstützung, einer stabilen Userspace-Schnittstelle und einer großen Entwicklergemeinschaft. Diese Stärken sind zugleich mit einer erheblichen internen Komplexität verbunden. Speicherverwaltung, VFS, Netzwerk, Treiber, Security-Frameworks, Namespaces, cgroups, Scheduler und zahlreiche Architekturpfade leben innerhalb eines umfangreichen Kernels und müssen miteinander kompatibel bleiben.

Qyronex Kernal setzt an einem anderen Punkt an. Statt die Linux-Architektur als interne Vorlage zu übernehmen, wird Linux zunächst als **externe Verhaltensschnittstelle** betrachtet. Die zentrale Forschungsfrage lautet daher:

> Kann ein Capability-orientierter, überwiegend in Rust entwickelter Hybridkernel einen relevanten Linux-Userspace ausführen, ohne die interne Linux-Autoritäts- und Subsystemarchitektur zu reproduzieren?

Diese Frage hat mehrere Teilaspekte:

1. Wie kann Autorität expliziter als in klassischen global erreichbaren Kernelpfaden modelliert werden?
2. Wie weit kann Rust die Menge speicherunsicherer Implementierung reduzieren, ohne Hardware- und ABI-nahe Arbeiten unmöglich zu machen?
3. Welche Linux-Semantik muss tatsächlich nachgebildet werden, damit unveränderte Anwendungen funktionieren?
4. Welche Kosten entstehen durch die Übersetzung zwischen Linux-Semantik und einem abweichenden internen Objektmodell?
5. Wie lässt sich verhindern, dass Kompatibilitätstests zu „Fake Success“ oder programmspezifischen Sonderfällen führen?

Qyronex Kernal beantwortet diese Fragen nicht durch einen einzelnen Mechanismus, sondern durch eine Kombination aus Capability-Modell, expliziten Speicherinvarianten, modularen Rust-Crates, architekturspezifischen Backends und einer beweisorientierten Debian-Kompatibilitätsstrategie.

## 2. Forschungsgegenstand und Abgrenzung

Qyronex Kernal ist ein experimentelles Betriebssystemprojekt. Der aktuelle primäre Runtime-Pfad ist AArch64/ARM64. Der Quellbaum enthält zusätzlich x86_64-Komponenten und zahlreiche gemeinsam genutzte Subsysteme. Die Workspace-Struktur umfasst unter anderem ABI-Crates, Boot-/ELF-Code, Firmwareparser, Capability- und Objektmodelle, Prozess- und Scheduler-Komponenten, virtuelle Speicherverwaltung, Usercopy, Futexe, Signale, VFS/FD-Logik und Linux-Kompatibilität.

Der Untersuchungsgegenstand ist nicht „ein besseres Linux“ im pauschalen Sinn. Linux hat eine Reife, Hardwareabdeckung und betriebliche Validierung, die ein Forschungsprojekt nicht kurzfristig erreichen kann. Die relevante Vergleichsebene ist die **Architekturentscheidung**:

- Linux: sehr breiter, monolithischer Kernel mit modularen Subsystemen und Loadable Modules;
- Qyronex Kernal: Capability-orientierter Hybridansatz mit stärkerer Betonung von expliziten Autoritätsgrenzen und der Möglichkeit, Dienste beziehungsweise Treiber stärker zu isolieren.

Die Bezeichnung „Hybridkernel“ wird hier funktional verwendet: Nicht jede Betriebssystemfunktion muss zwangsläufig im minimal privilegierten Kern verbleiben, während gleichzeitig leistungs- oder ABI-kritische Mechanismen kernel-nah implementiert werden können.

## 3. Methodik

Die Arbeit verwendet vier methodische Ebenen.

### 3.1 Quellcode- und Architekturinspektion

Die Repository-Struktur und die dokumentierten Invarianten werden als Primärquelle für das Qyronex-Design betrachtet. Maßgeblich sind insbesondere BootInfo/Handoff, Memory-Layout, Capability- und Objektpfade, Linux-ABI-Schichten, Secure-Storage-Architektur und die Debian-13-Kompatibilitätsroadmap.

### 3.2 Vergleich mit Linux

Für Linux werden die offiziellen Kernel-Dokumentationen zu VFS, Speicherverwaltung, Credentials, Security und Namespaces herangezogen. Der Vergleich betrifft keine einzelne Linux-Version im Sinne einer historischen 0.x-Implementierung, sondern das klassische Architekturmodell des Linux-Kernels als monolithischen, modularen General-Purpose-Kernel.

### 3.3 Verhalten statt Quellcodeähnlichkeit

Linux-Kompatibilität wird über beobachtbares Verhalten bewertet. Zwei Kernel müssen intern nicht dieselben Datenstrukturen verwenden, solange der Userspace an der definierten ABI-Grenze die erforderliche Semantik erhält.

### 3.4 Referenzorakel

Qyronex nutzt für Debian-13-Arbeit einen gepinnten Referenzpfad. Tests werden in einer verifizierten Debian-Umgebung ausgeführt; Rückgabewerte, Fehler, Signale, Metadaten, relevante Pfade und weitere Beobachtungen werden erfasst und mit Qyronex verglichen. Dadurch wird zwischen Implementierung und tatsächlich nachgewiesener Kompatibilität unterschieden.

## 4. Klassischer Linux-Kernel als Vergleichsmodell

Linux wird üblicherweise als monolithischer Kernel beschrieben, wobei „monolithisch“ nicht bedeutet, dass der Code unstrukturiert wäre. Linux besitzt klar getrennte Subsysteme, modulare Treiber und umfangreiche interne APIs. Wesentliche Betriebssystemdienste – Speicherverwaltung, Scheduler, VFS, Netzwerkstack, große Teile der Treiberinfrastruktur und Sicherheitsmechanismen – laufen jedoch grundsätzlich im Kerneladressraum.

### 4.1 Linux-VFS

Das Linux Virtual File System stellt eine einheitliche Dateisystemschnittstelle bereit. Dentries, Inodes, File-Objekte und dateisystemspezifische Operationsstrukturen bilden die Abstraktionsschicht zwischen Systemaufrufen und konkreten Dateisystemen. Ein offener Dateideskriptor verweist kernelintern auf ein File-Objekt; Pfadauflösung arbeitet unter anderem mit Dentry- und Inode-Strukturen.

### 4.2 Linux-Speicherverwaltung

Linux verwaltet virtuellen Speicher, Demand Paging, Userspace-Adressräume, Kernelallokationen, Page Cache, File Mappings, Reclaim, NUMA und zahlreiche Spezialmechanismen. Diese Funktionsbreite ist ein Maßstab für Reife, aber auch ein Hinweis auf die Komplexität einer vollständigen Linux-kompatiblen Umgebung.

### 4.3 Linux-Credentials und Security

Linux kombiniert klassische UNIX-Credentials wie UID/GID mit Capabilities, ACLs und optionalen Mandatory-Access-Control-Systemen über LSM. Linux-Capabilities zerlegen traditionelle Root-Privilegien in Teilrechte. Dieses Modell ist leistungsfähig, unterscheidet sich jedoch konzeptionell von Object-Capability-Systemen: Eine Linux-Capability wie `CAP_NET_ADMIN` ist ein privilegienbezogenes Recht einer Task, während eine Object Capability typischerweise direkt auf eine konkrete Ressource oder einen konkreten Authority-Handle verweist.

### 4.4 Sicherheits-Härtung

Linux verfügt über umfangreiche Self-Protection-Mechanismen, darunter W^X-nahe Richtlinien, Trennung von Kernel- und Userspace-Speicher, SMEP/SMAP beziehungsweise PAN/PXN auf unterstützten Architekturen, LSM, seccomp und zahlreiche Hardening-Optionen. Qyronex darf daher nicht so dargestellt werden, als seien Prinzipien wie W^X oder expliziter Usercopy exklusiv neu. Der Unterschied liegt vor allem darin, dass das Qyronex-Design versucht, Capability- und Ownership-Grenzen als primäre Architekturstruktur zu verwenden.

## 5. Architektur von Qyronex Kernal

### 5.1 Modularer Rust-Workspace

Der Quellbaum ist in viele kleine Crates aufgeteilt. Beispiele sind `kernel/capability`, `kernel/object`, `kernel/process`, `kernel/vm`, `kernel/usercopy`, `kernel/linux-vfs`, `kernel/linux-signal`, `kernel/linux-futex`, `abi/linux-aarch64`, `firmware/fdt` und verschiedene Architekturbackends.

Diese Aufteilung hat zwei Ziele: erstens kleinere überprüfbare Verantwortungsbereiche, zweitens eine klare Trennung zwischen architekturspezifischer Mechanik und gemeinsamem Policy-/Semantikcode.

### 5.2 Capability-orientierte Autorität

Eine Capability ist im Qyronex-Zielmodell nicht nur ein boolesches Privileg, sondern ein explizites Recht auf ein Objekt oder einen eng definierten Ressourcenbereich. Der Sicherheitsgewinn entsteht dann, wenn ein Prozess keine globale Operation ausführen kann, nur weil er den Namen oder Pfad einer Ressource kennt.

Das Modell soll für IPC, Speicher, Geräte, Storage und andere Kernelobjekte gelten. Für Linux-Kompatibilität muss eine klassische API wie `openat()` intern in capability-autorisierte Objektoperationen übersetzt werden.

### 5.3 Kleiner privilegierter Kern als Ziel

Der Ansatz versucht, möglichst wenig implizite Autorität im privilegierten Kern zu bündeln. Das bedeutet nicht, dass jedes Subsystem bereits aus dem Kernel herausgezogen ist. Vielmehr ist es eine Entwurfsrichtung: Treiber- und Servicegrenzen sollen so definiert sein, dass Isolation möglich ist, ohne die Userspace-ABI zu verändern.

## 6. Rust als Implementierungssprache

Rust kann Klassen typischer Speicherfehler – etwa Use-after-free, Data Races in sicherem Rust oder viele Out-of-bounds-Zugriffe – strukturell erschweren. Betriebssystemcode benötigt dennoch `unsafe`, weil Seitentabellen, MMIO, Interruptzustand, Kontextwechsel und rohe Speicherbereiche nicht vollständig in sicheren Sprachabstraktionen ausgedrückt werden können.

Die relevante Sicherheitsfrage ist daher nicht, ob `unsafe` vollständig verschwindet, sondern ob es **klein, lokal, begründet und auditierbar** bleibt.

Qyronex formuliert hierfür eine einfache Regel: unsichere Operationen sollen mit einer `SAFETY:`-Begründung an die jeweils notwendige Invariante gebunden werden.

Rust verhindert außerdem keine logischen Autorisierungsfehler. Ein perfekt speichersicherer Codepfad kann trotzdem einem falschen Prozess Zugriff auf ein Objekt gewähren. Deshalb müssen Typsicherheit und Capability-Modell zusammen betrachtet werden.

## 7. Boot und Vertrauensübergang

Ein Betriebssystem beginnt seine Sicherheitsgeschichte vor dem ersten Userspace-Prozess. Qyronex verwendet einen versionierten BootInfo-Vertrag zwischen UEFI-Loader und Kernel. Firmwaredaten werden normalisiert, unbekannte Speichertypen konservativ behandelt und Bereiche erst nach explizitem Ownership-Übergang freigegeben.

Dieses Vorgehen reduziert die Menge impliziter Firmwareannahmen im Kernel. Der zentrale Gedanke ist übertragbar: Jeder Übergang zwischen Vertrauensdomänen sollte Daten normalisieren, Grenzen prüfen und Ownership eindeutig festlegen.

Linux muss wegen seiner Plattformbreite wesentlich mehr Bootkonfigurationen, Firmwarepfade und Legacy-Szenarien unterstützen. Qyronex kann im Forschungsstadium einen engeren Vertrag wählen und dadurch Invarianten leichter formalisieren.

## 8. Speicherverwaltung

Qyronex definiert mehrere harte Invarianten:

- kein gleichzeitig schreibbarer und ausführbarer Kernelbereich;
- Nullseite ungemappt;
- Guard Pages für sensible Stacks;
- klare User-/Kernel-Zugriffsrechte;
- explizite Usercopy-Grenzen;
- NX für MMIO;
- Ownership vor Wiederverwendung physischer Frames.

Linux verfolgt viele dieser Schutzziele ebenfalls, besitzt aber zusätzlich eine wesentlich breitere VM-Funktionalität. Ein fairer Vergleich muss daher zwischen **Sicherheitsprinzip** und **Funktionsumfang** unterscheiden.

Die Forschungsfrage für Qyronex lautet nicht, ob es heute Linux-MM ersetzt, sondern ob ein kleineres System diese Regeln von Anfang an systematisch durchziehen kann, während später Demand Paging, File Mappings, Shared Memory und weitere Linux-Verträge ergänzt werden.

## 9. Prozesse, Threads und Scheduling

Linux verwendet `task_struct` als zentrale Prozess-/Threadstruktur und verbindet Schedulerzustand, Credentials, Namespaces und zahlreiche weitere Subsysteme. Qyronex zerlegt entsprechende Funktionalität stärker in dedizierte Crates und versucht, Lifecycle-Ereignisse explizit zu modellieren.

Für Linux-Kompatibilität sind besonders schwierig:

- `clone`/Thread-Erzeugung;
- Eltern-/Kindbeziehungen;
- Exit und Zombie-Zustände;
- `wait*`;
- Thread-IDs und `set_tid_address`;
- Signalzustellung;
- Futex-Wakeup und atomare Zustandsübergänge;
- `execve` mit korrekter Ablösung alter Prozessressourcen.

Diese Semantik ist nicht bloß API-Oberfläche. Sie definiert Race Conditions und beobachtbare Ordnungen, die glibc, pthreads und systemd voraussetzen.

## 10. Linux-ABI als Kompatibilitätsschicht

Ein Kernpunkt des Projekts ist die Trennung zwischen **Linux ABI** und **Linux interner Architektur**.

Ein Systemaufruf wie `read`, `mmap`, `clone` oder `rt_sigaction` muss aus Sicht eines Linux-Programms die erwartete Semantik besitzen. Intern kann er jedoch auf andere Objekte, andere Autoritätsprüfungen und andere Lifecycle-Strukturen abgebildet werden.

Vorteile dieses Ansatzes:

- interne Sicherheitsmodelle können unabhängig von Linux weiterentwickelt werden;
- Userspace-Kompatibilität muss nicht automatisch Linux-internen globalen Zustand importieren;
- Tests können auf externe Semantik fokussieren.

Nachteile:

- Übersetzungslogik wird umfangreich;
- semantische Randfälle müssen trotzdem exakt nachgebildet werden;
- Performance kann durch zusätzliche Indirektion oder Objektgrenzen leiden;
- Entwickler müssen zwei Modelle gleichzeitig verstehen.

## 11. VFS und Dateideskriptoren

Linux VFS abstrahiert konkrete Dateisysteme über Dentries, Inodes und File-Objekte. Qyronex benötigt für Linux-Programme vergleichbare beobachtbare Dateideskriptor- und Pfadsemantik, will diese aber auf capability-autorisierte Handles abbilden.

Eine zentrale These lautet:

> Ein Pfad identifiziert eine Ressource, aber er soll nicht automatisch Autorität über diese Ressource verleihen.

Das ist besonders relevant für Multi-Tenant-Systeme und sichere Storage-Services. Linux erreicht Isolation traditionell über UID/GID, Mount-/User-Namespaces, Dateirechte, ACLs, LSM und weitere Schichten. Qyronex möchte zusätzlich die Ressourcendelegation selbst als Capability-Problem behandeln.

## 12. Sichere Speicherarchitektur

Die Storage-Architektur geht über klassische Dateisystemkompatibilität hinaus. Geplant sind:

- Capability-gebundene Storage-Autorität;
- hierarchische Schlüssel;
- Verschlüsselung und Integrität;
- authentifizierte Metadaten;
- IOMMU-begrenztes DMA;
- generationensichere asynchrone Queues;
- kontrollierte Low-/Zero-Copy-Pfade;
- Crash-Konsistenz und explizite Recoveryzustände.

Der Ansatz unterscheidet sich von der typischen Situation, in der Verschlüsselung oder Mandantentrennung erst oberhalb eines allgemeinen Block-/VFS-Stacks ergänzt werden. Qyronex formuliert die Trennung als Architekturvertrag des Storage-Pfads.

Die zentrale technische Herausforderung ist, dass Sicherheit und Performance nicht getrennt optimiert werden können. Zero-Copy kann beispielsweise die Performance verbessern, erhöht aber Anforderungen an Buffer Ownership, DMA-Lifetime und Key-/Plaintext-Lebensdauer.

## 13. Geräte und DMA

Ein monolithischer Kernel wie Linux führt viele Treiber im privilegierten Adressraum aus. Linux enthält zugleich IOMMU-, DMA-API- und zahlreiche Hardening-Mechanismen. Qyronex verfolgt als Ziel eine stärkere Capability- und IOMMU-gebundene Geräteautorität.

Die relevante Sicherheitsannahme lautet: Ein Gerät oder Treiber soll nur auf explizit freigegebene Puffer zugreifen können. Vor Wiederverwendung eines Frames müssen DMA-Mappings widerrufen beziehungsweise invalidiert sein.

Das reduziert nicht automatisch alle Treiberrisiken. Fehlerhafte Interrupt-, Queue- oder Lifecycle-Logik bleibt möglich. Der Vorteil liegt in einer kleineren maximalen Schadensdomäne, wenn die Isolation korrekt umgesetzt ist.

## 14. Debian 13 als Kompatibilitätsziel

Ein unveränderter Debian-Userspace ist ein anspruchsvolles Ziel, weil moderne Distributionen weit mehr erwarten als eine kleine POSIX-Syscallmenge.

Zu den relevanten Abhängigkeiten gehören:

- dynamischer Loader und glibc;
- pthreads und Futexe;
- vollständige Signalpfade;
- TTY/PTY und Job Control;
- `/proc`, `/sys`, `/dev`;
- AF_UNIX und IP-Netzwerk;
- epoll, eventfd, timerfd, signalfd, inotify;
- Namespaces und cgroups v2;
- systemd als PID 1;
- udev und Uevents;
- robuste Dateisystemsemantik für `dpkg`/`apt`.

Qyronex unterteilt dieses Ziel in nachweisbare Schritte. Erst nach erfolgreicher Ausführung der jeweiligen Referenztests darf ein Kompatibilitätszustand als bewiesen markiert werden.

## 15. Das Referenzorakel als wissenschaftliche Methode

Ein häufiger Fehler in Kompatibilitätsprojekten ist die Gleichsetzung von „Syscall vorhanden“ mit „Syscall kompatibel“. Qyronex begegnet diesem Problem mit einem Referenzorakel.

Das Verfahren:

1. einen Testfall definieren;
2. ihn in einer gepinnten Debian-Referenzumgebung ausführen;
3. beobachtbare Ergebnisse erfassen;
4. denselben Vertrag unter Qyronex ausführen;
5. Unterschiede automatisch oder manuell bewerten;
6. erst danach den Kompatibilitätsstatus anheben.

Besonders wichtig ist die Provenienzbindung an Source-Commit und Referenzimage. Ohne diese Bindung könnte alte Evidenz fälschlich für einen veränderten Kernelzustand gelten.

## 16. Vergleichstabelle Qyronex Kernal und klassischer Linux-Kernel

| Dimension | Klassischer Linux-Kernel | Qyronex Kernal |
| --- | --- | --- |
| Reife | jahrzehntelang produktiv erprobt | Forschungs-/Entwicklungsprojekt |
| Kernelmodell | monolithisch, stark modularisiert | Capability-orientierter Hybridansatz |
| Hauptsprache | überwiegend C, zunehmend Rust in Teilbereichen | überwiegend Rust, `unsafe` für Hardwaregrenzen |
| Autorität | UID/GID, Linux Capabilities, ACL, LSM, Namespaces u. a. | Object-Capability-orientierte Zielarchitektur plus Linux-Kompatibilität |
| VFS | ausgereiftes Dentry/Inode/File-Modell | capability-gestützte VFS-/FD-Schicht im Aufbau |
| VM | sehr breit: Demand Paging, NUMA, Reclaim, Swap, Page Cache usw. | deutlich kleinerer Funktionsumfang, harte Invarianten als Designkern |
| Treiber | sehr breite In-Kernel-Treiberbasis | begrenzte Abdeckung, stärkere Isolation als Ziel |
| ABI | native Linux-ABI | Linux-ABI wird als Kompatibilitätsschicht nachgebildet |
| Distribution | vollständige Linux-Distributionen | Debian-13-Kompatibilität schrittweise in Arbeit |
| Sicherheitsnachweis | vielfältige Hardening-/Test-/Audit-Ökosysteme | projektinterne Gates, negative Tests und Referenzorakel |
| Produktion | breit produktiv eingesetzt | ausdrücklich nicht produktionsreif |

## 17. Sicherheitsanalyse

### 17.1 Reduktion ambienter Autorität

Object Capabilities können das Principle of Least Authority unterstützen, weil Zugriff über explizit delegierte Handles statt über global interpretierbare Namen erfolgt. Der Sicherheitsgewinn hängt jedoch davon ab, ob Capabilities tatsächlich nicht fälschbar, generationensicher und widerrufbar beziehungsweise lifecycle-sicher implementiert sind.

### 17.2 Rust und Memory Safety

Rust reduziert die Wahrscheinlichkeit bestimmter Fehlerklassen, beseitigt aber weder logische Bugs noch Hardwarefehlkonfiguration, Seitenfehler in `unsafe`, TOCTOU-Probleme oder falsche Capability-Zuordnung. Deshalb sind negative Tests und kleine `unsafe`-Grenzen notwendig.

### 17.3 Kompatibilität als Angriffsfläche

Jede zusätzliche Linux-Semantik vergrößert den erreichbaren Code. Eine Kompatibilitätsschicht kann damit selbst zur Angriffsfläche werden. Der fail-closed Grundsatz – unbekannte Operationen explizit ablehnen – ist deshalb sicherer als ein optimistischer Stub, der scheinbaren Erfolg zurückgibt.

### 17.4 Monolithischer Kernel versus Isolation

Ein stärker isoliertes Design kann Fehlerdomänen verkleinern, verursacht aber IPC-, Mapping- und Kontextgrenzen. Ein monolithischer Kernel kann direkte Funktionsaufrufe und gemeinsam genutzte Datenstrukturen effizient einsetzen. Die Behauptung, ein Ansatz sei grundsätzlich schneller oder sicherer, wäre ohne Messung unzulässig.

## 18. Performancebetrachtung

Die Performancehypothese von Qyronex basiert nicht auf der Annahme, dass Isolation kostenlos ist. Vielmehr sollen Mehrkosten durch folgende Techniken begrenzt werden:

- asynchrone Queue-Modelle;
- Batching;
- per-CPU oder geshardete Strukturen;
- begrenzte Kopierpfade;
- explizite Ownership statt globaler Locks;
- architekturspezifische Beschleunigung dort, wo Semantik identisch bleibt.

Eine wissenschaftlich belastbare Bewertung benötigt Messungen für:

- Syscall-Latenz;
- Kontextwechsel;
- Futex-Contention;
- Scheduler-Skalierung;
- VFS-/FD-Operationen;
- sequenziellen Storage-Durchsatz;
- Random IOPS;
- Netzwerkdurchsatz und Latenz;
- Crypto-Overhead;
- Mehrkernskalierung.

Solange diese Daten nicht reproduzierbar vorliegen, enthält diese Arbeit keine erfundenen Performancevorteile gegenüber Linux.

## 19. Forschungsfragen und Hypothesen

### H1 – Explizite Capability-Autorität reduziert unbeabsichtigte Rechteausbreitung

Erwartung: Wenn Ressourcen nur über delegierte, generationensichere Capabilities erreichbar sind, sinkt die Zahl von Pfaden, über die ein kompromittierter Prozess fremde Ressourcen allein durch Namenskenntnis erreicht.

Prüfung: negative Cross-Tenant-, stale-handle- und revoke-Tests.

### H2 – Rust verkleinert den speicherunsicheren Auditbereich

Erwartung: Der Anteil von Code, der rohe Pointer, MMIO, Seitentabellen und Kontextwechsel direkt manipuliert, kann auf kleine `unsafe`-Grenzen konzentriert werden.

Prüfung: statische Auswertung der `unsafe`-Blöcke, Safety-Kommentare, Miri/Hosttests soweit möglich, Fuzzing für Parser und ABI-Grenzen.

### H3 – Linux-Userspace-Kompatibilität ist ohne Linux-interne Architektur möglich

Erwartung: Ein ausreichend großer Userspace kann funktionieren, wenn externe Syscall-/VFS-/Prozesssemantik korrekt ist, obwohl intern Capabilities und andere Ownership-Strukturen verwendet werden.

Prüfung: gepinnte Debian-Referenzfälle bis hin zu systemd/apt.

### H4 – Isolation kann mit Queue-orientierten Datenpfaden performanceverträglich gestaltet werden

Erwartung: Batching, asynchrone Queues und kontrolliertes Zero-/Low-Copy können einen Teil der Kosten zusätzlicher Schutzgrenzen kompensieren.

Prüfung: Storage-, IPC- und Netzwerkbenchmarks gegen definierte Linux-Baselines.

## 20. Evaluationsplan

Eine vollständige Evaluation sollte mindestens fünf Ebenen enthalten.

### 20.1 Funktionalität

- reproduzierbarer Boot;
- Userspace-ELF;
- Prozesse/Threads;
- Signal/Futex;
- VFS;
- Netzwerk;
- dynamischer Loader;
- systemd und Paketmanager.

### 20.2 Sicherheit

- Capability-Isolation;
- Cross-Tenant-Negativtests;
- W^X- und Nullseitenprüfung;
- Guard-Page-Tests;
- Usercopy-Grenzen;
- DMA-Negativtests;
- Storage-Integritäts- und Wrong-Key-Tests.

### 20.3 Robustheit

- wiederholte Boots;
- Prozess- und Thread-Stress;
- Dateisystem-Crashszenarien;
- Netzwerk- und Storage-Last;
- Ressourcenerschöpfung;
- lange Mixed-Workload-Läufe.

### 20.4 Kompatibilität

- Referenzorakel;
- glibc/pthread;
- ausgewählte Linux-Testfälle;
- systemd/udev;
- `dpkg`/`apt`;
- dokumentierte `ENOSYS`-Grenzen.

### 20.5 Performance

- gleiche Hardware oder kontrollierte VM-Konfiguration;
- identische Workloads;
- Warm-/Cold-Cache getrennt;
- Median, Perzentile und Varianz;
- CPU-Zeit und Speicherverbrauch zusätzlich zum Durchsatz.

## 21. Limitationen

Die wesentlichen Einschränkungen des aktuellen Projektstands sind:

1. Qyronex ist nicht produktionsreif.
2. Die Hardwareabdeckung ist gegenüber Linux sehr klein.
3. Die vollständige Debian-13-Kompatibilität ist ein Ziel, kein bereits vollständig nachgewiesener Zustand.
4. Ein Capability-Design ist nicht automatisch sicher; Implementierungs- und Delegationsfehler bleiben möglich.
5. Rust reduziert bestimmte Fehlerklassen, ersetzt aber weder Architekturprüfung noch Fuzzing und Laufzeittests.
6. Für belastbare Performanceaussagen fehlen an vielen Stellen vollständige vergleichende Benchmarks.
7. Das Projekt besitzt nicht die jahrzehntelange externe Begutachtung und Nutzerbasis von Linux.

Diese Grenzen sind zentral für eine wissenschaftlich faire Interpretation. Ein neuer Kernel sollte nicht anhand seiner Designziele mit einem etablierten Produktionskernel gleichgesetzt werden.

## 22. Diskussion

Qyronex Kernal ist besonders interessant als Experiment zur **Entkopplung von Kompatibilität und interner Autorität**. Viele alternative Betriebssysteme verzichten auf breite Linux-Kompatibilität und gewinnen dadurch Designfreiheit. Andere Projekte übernehmen große Teile einer bestehenden Unix-/Linux-inspirierten Architektur, um Kompatibilität schneller zu erreichen.

Qyronex versucht einen Mittelweg: Der Userspace soll möglichst wenig Anpassungen benötigen, während der Kernel intern andere Sicherheitsprimitiven nutzen kann. Dieser Ansatz ist ambitioniert, weil die Linux-ABI sehr viel mehr als eine Syscallnummerntabelle umfasst. Semantik entsteht aus Wechselwirkungen zwischen Scheduler, Signalen, Futexen, VM, VFS, TTY, Netzwerk, Credentials und Device Model.

Der Referenzorakel-Ansatz ist deshalb ein wesentlicher methodischer Bestandteil. Er verhindert zwar keine Bugs, schafft aber eine klare epistemische Grenze: Was nicht gegen die Referenz ausgeführt wurde, gilt nicht als bewiesen.

## 23. Schlussfolgerung

Die Untersuchung zeigt, dass Qyronex Kernal ein kohärentes Forschungsziel verfolgt: eine Capability-orientierte interne Architektur, Rust-basierte Implementierung und Linux-Userspace-Kompatibilität sollen nicht als gegenseitig ausschließend behandelt werden.

Im Vergleich zum klassischen Linux-Kernel liegt die Stärke des Projekts nicht in heutiger Funktionsbreite oder Reife. Linux ist in diesen Kategorien deutlich überlegen. Der wissenschaftliche Beitrag des Qyronex-Ansatzes liegt vielmehr in der Frage, ob Autorität, Speicherbesitz, DMA und Storage von Beginn an expliziter modelliert werden können, während eine externe Linux-ABI schrittweise nachgebaut wird.

Für eine erfolgreiche Weiterentwicklung sind drei Prinzipien entscheidend:

1. **Keine Kompatibilitätsbehauptung ohne ausführbare Evidenz.**
2. **Keine Sicherheitsinvariante für kurzfristigen Userspace-Erfolg aufweichen.**
3. **Keine Performancebehauptung ohne reproduzierbare Vergleichsmessung.**

Wenn diese Disziplin beibehalten wird, kann Qyronex Kernal als Forschungsplattform wertvoll sein, um Capability-Systeme, moderne Systemsprache, isolierte I/O-Pfade und Linux-Userspace-Kompatibilität gemeinsam zu untersuchen.

---

## Literatur und Primärquellen

### Qyronex-Kernal-Projektquellen

1. Qyronex Kernal, `README.md` und `README_DE.md`.
2. Qyronex Kernal, `docs/BOOT_PROTOCOL.md`.
3. Qyronex Kernal, `docs/MEMORY_LAYOUT.md`.
4. Qyronex Kernal, `SECURE_STORAGE_ARCHITECTURE.md`.
5. Qyronex Kernal, `DEBIAN_13_COMPATIBILITY_ROADMAP.md`.
6. Qyronex Kernal, `docs/debian13/README.md`.

### Linux-Referenzen

7. Linux Kernel Documentation: Overview of the Linux Virtual File System. https://docs.kernel.org/filesystems/vfs.html
8. Linux Kernel Documentation: Memory Management. https://docs.kernel.org/admin-guide/mm/
9. Linux Kernel Documentation: Credentials in Linux. https://docs.kernel.org/security/credentials.html
10. Linux Kernel Documentation: Kernel Self-Protection. https://docs.kernel.org/security/self-protection.html
11. Linux Kernel Documentation: Namespaces. https://docs.kernel.org/admin-guide/namespaces/
12. Linux Kernel Documentation: Linux Security Module Usage. https://docs.kernel.org/admin-guide/LSM/

## Anhang A – Kurzdefinitionen

**Capability:** Nicht fälschbares beziehungsweise kontrolliert erzeugtes Recht, auf ein Objekt oder eine Operation zuzugreifen.

**Ambient Authority:** Autorität, die einer Komponente implizit durch globale Identität oder Umgebung zur Verfügung steht, statt explizit delegiert zu werden.

**W^X:** Richtlinie, nach der Speicher nicht gleichzeitig schreibbar und ausführbar sein soll.

**Userspace ABI:** Binäre beziehungsweise semantische Schnittstelle zwischen Anwendungen/Libraries und Kernel.

**Referenzorakel:** Ausführung derselben begrenzten Probe in einer bekannten Referenzumgebung, deren beobachtbares Verhalten als Vergleichsbasis dient.

**Hybridkernel:** Architektur, die Mechanismen eines monolithischen Kernels mit stärker ausgelagerten oder isolierbaren Diensten kombiniert.

## Anhang B – Empfohlene zukünftige Messreihen

- 1/2/4/8-Kern Scheduler-Skalierung;
- Futex Ping-Pong und Contention;
- `fork`/`clone`/`execve`-Kosten;
- Page-Fault-Latenz;
- Pipe- und Unix-Socket-Durchsatz;
- VFS-Metadatenoperationen;
- sequenzieller und zufälliger Block-I/O;
- Crypto-on/off-Vergleich für geschützten Storage;
- Netzwerk RTT und Throughput;
- systemd-Service-Startzeit;
- Paketmanager-Transaktionsdauer;
- 24-Stunden-Mixed-Stress mit Leak-/Panic-Auswertung.
