# Ghost Recon Wildlands — Intel Hybrid CPU Fix

Small tools for **Ghost Recon Wildlands startup issues on Intel P-core / E-core CPUs**.

This repository contains:

* `wildlands_pcore_wrapper.py` — launches Wildlands on P-cores only.
* `wildlands_startup_logger_v2.py` — logs the normal startup without changing CPU affinity.
* `wildlands_deep_logger_v4.py` — performs a deeper startup analysis with threads, I/O and Windows tracing.

---

# English

## P-Core Wrapper

### Requirements

* Windows 10/11
* Python 3 64-bit added to `PATH`

Check Python in PowerShell:

```powershell
python --version
```

### Installation

Put these files next to `GRW.exe`:

```text
wildlands_pcore_wrapper.py
launch_wildlands_pcores.bat
```

Then run:

```text
launch_wildlands_pcores.bat
```

The wrapper automatically detects the P-cores and launches `GRW.exe` using only them.

Tested on:

```text
Intel Core i5-13600K
6 P-cores / 8 E-cores
P-core mask: 0xFFF
```

On this system, the game starts successfully but can remain on the splash screen for **2–3 minutes**.

No DLL injection, no game modification and no BIOS change.

---

## Startup Logger

Use the logger if you want to help investigate the startup problem.

Install `psutil` in PowerShell:

```powershell
python -m pip install psutil
```

Put these files next to `GRW.exe`:

```text
wildlands_startup_logger_v2.py
launch_wildlands_logger_v2.bat
```

Run:

```text
launch_wildlands_logger_v2.bat
```

The logger launches Wildlands normally through Steam **without changing CPU affinity**.

Leave the splash screen running for several minutes.

A CSV file is automatically created with:

* GRW.exe CPU usage
* P-core / E-core usage
* RAM
* threads
* I/O
* PID changes
* startup time

Example:

```text
wildlands_startup_20260812_231649.csv
```

If you share a log, please include your exact CPU model.

---

## Deep Startup Logger V4

The V4 logger is for a **deeper investigation of what `GRW.exe` is actually doing during the splash screen**.

It still launches Wildlands normally through Steam and **does not change CPU affinity**.

Install `psutil` if needed:

```powershell
python -m pip install psutil
```

Put these files next to `GRW.exe`:

```text
wildlands_deep_logger_v4.py
launch_wildlands_deep_logger_v4.bat
```

Then run:

```text
launch_wildlands_deep_logger_v4.bat
```

Windows may request administrator rights for system tracing.

Each test creates a folder containing:

```text
telemetry.csv
events.log
summary.txt
manifest.json
wildlands.etl
```

The V4 records additional information such as:

* individual GRW.exe thread activity
* context switches
* loaded modules
* open files
* network activity
* Steam / Ubisoft / EAC processes
* Windows ETW CPU call stacks

The `wildlands.etl` file can be opened with **Windows Performance Analyzer** to inspect where `GRW.exe` actually spends CPU time.

### Optional Process Monitor trace

If `Procmon64.exe` is placed next to the V4 logger, it can also create:

```text
wildlands_procmon.pml
```

This provides additional file system and registry tracing.

If you share a V4 trace, please include your exact CPU model.

---

# Français

## Wrapper P-Core

### Prérequis

* Windows 10/11
* Python 3 64 bits ajouté au `PATH`

Vérification dans PowerShell :

```powershell
python --version
```

### Installation

Placez ces fichiers à côté de `GRW.exe` :

```text
wildlands_pcore_wrapper.py
launch_wildlands_pcores.bat
```

Puis lancez :

```text
launch_wildlands_pcores.bat
```

Le wrapper détecte automatiquement les P-cores et lance `GRW.exe` uniquement dessus.

Testé sur :

```text
Intel Core i5-13600K
6 P-cores / 8 E-cores
Masque P-core : 0xFFF
```

Sur cette configuration, le jeu démarre correctement mais peut rester **2 à 3 minutes** sur le splash screen.

Aucune injection DLL, aucune modification du jeu et aucun changement BIOS.

---

## Logger de démarrage

Le logger permet d'étudier le problème sans modifier l'affinité CPU.

Installez `psutil` dans PowerShell :

```powershell
python -m pip install psutil
```

Placez ces fichiers à côté de `GRW.exe` :

```text
wildlands_startup_logger_v2.py
launch_wildlands_logger_v2.bat
```

Puis lancez :

```text
launch_wildlands_logger_v2.bat
```

Laissez le splash screen tourner plusieurs minutes même si le jeu semble bloqué.

Le logger crée automatiquement un fichier CSV contenant :

* CPU de GRW.exe
* activité P-core / E-core
* RAM
* threads
* I/O
* changements de PID
* temps de démarrage

Si vous partagez un log, indiquez également votre modèle exact de processeur.

---

## Deep Startup Logger V4

Le logger V4 permet d'aller **beaucoup plus loin dans l'analyse de ce que fait réellement `GRW.exe` pendant le splash screen**.

Il lance toujours Wildlands normalement via Steam et **ne modifie pas l'affinité CPU**.

Installez `psutil` si nécessaire :

```powershell
python -m pip install psutil
```

Placez ces fichiers à côté de `GRW.exe` :

```text
wildlands_deep_logger_v4.py
launch_wildlands_deep_logger_v4.bat
```

Puis lancez :

```text
launch_wildlands_deep_logger_v4.bat
```

Windows peut demander les droits administrateur pour la capture système.

Chaque test crée un dossier contenant notamment :

```text
telemetry.csv
events.log
summary.txt
manifest.json
wildlands.etl
```

La V4 enregistre également :

* activité individuelle des threads de GRW.exe
* changements de contexte
* modules chargés
* fichiers ouverts
* activité réseau
* processus Steam / Ubisoft / EAC
* piles d'appels CPU via ETW

Le fichier `wildlands.etl` peut être ouvert avec **Windows Performance Analyzer** afin d'analyser où `GRW.exe` passe réellement son temps CPU.

### Trace Process Monitor optionnelle

Si vous placez `Procmon64.exe` à côté du logger V4, il peut également créer :

```text
wildlands_procmon.pml
```

Ce fichier permet une analyse supplémentaire des accès fichiers et registre.

Si vous partagez une trace V4, indiquez également votre modèle exact de processeur.
