# WannaCry Reverse Engineering Report

## Overview

This repository documents a **static reverse engineering analysis** of a WannaCry ransomware sample (`wannacry.exe`). The analysis was conducted in a controlled **Linux-based environment** using static analysis tools such as `file`, `strings`, and **Ghidra**. **Dynamic execution was intentionally not performed** to avoid accidental propagation or system compromise.

This document reflects the **current stage of analysis only**. Subsequent iterations will expand into payload (`taskche.exe`) decompilation, cryptographic routines, ransomware logic, and deeper network behavior.

---

## Sample Information

### File Listing

```bash
$ ls
32f24601153be0885f11d62e0a8a2f0280a2034fc981d8184180c5d3b1b9e8cf.zip
wannacry.exe
```

### File Type

```bash
$ file wannacry.exe
wannacry.exe: PE32 executable for MS Windows 4.00 (GUI), Intel i386, 4 sections
```

**Architecture:** 32-bit (x86)
**Platform:** Microsoft Windows
**Subsystem:** GUI Application
**Format:** Portable Executable (PE)

---

## Cryptographic Hashes

| Algorithm | Hash                                                             |
| --------- | ---------------------------------------------------------------- |
| MD5       | d5dcd28612f4d6ffca0cfeaefd606bcf                                 |
| SHA1      | d5dcd28612f4d6ffca0cfeaefd606bcf                                 |
| SHA256    | 32f24601153be0885f11d62e0a8a2f0280a2034fc981d8184180c5d3b1b9e8cf |

These hashes uniquely identify the analyzed sample.

---

## Analysis Environment

Static analysis was performed on the following system:

* **OS:** Kubuntu 25.10 (Questing Quokka)
* **Kernel:** Linux 6.17.0-8-generic
* **Architecture:** x86_64
* **Desktop Environment:** KDE Plasma 6.4.5
* **Shell:** bash 5.2.37

>  The malware sample was **never executed** on this system.

---

## Notable Behavior Identified (Static Analysis)

### 1. Dropper and Payload Extraction

The executable operates in **two distinct modes**, controlled by the number of command-line arguments:

#### Initial Execution (`argc < 2`)

* Extracts an **embedded PE payload** from the executable’s **resources**
* Writes the payload to:

```
C:\Windows\taskche.exe
```

* Executes the dropped payload silently
* Terminates the original process

This behavior classifies `wannacry.exe` as a **dropper + loader**.

The payload extraction is performed using dynamically resolved Windows APIs:

* `CreateFileA`
* `WriteFile`
* `CloseHandle`

---

### 2. Windows Service-Based Persistence (`mssecsvc2.0`)

When executed with command-line arguments (service context), the malware interacts with the **Windows Service Control Manager (SCM)**:

* Opens SCM with full access
* Opens or interacts with an existing service named:

```
mssecsvc2.0
```

**Important clarification:**

* `mssecsvc2.0` is **not a separate executable**
* It is a **Windows service name** whose `ImagePath` points to:

```
C:\Windows\taskche.exe
```

The same binary therefore functions as:

* The ransomware runtime
* The Windows service executable

---

### 3. Service Failure Action Hardening

The malware configures service recovery behavior using:

```
ChangeServiceConfig2A(..., SERVICE_CONFIG_FAILURE_ACTIONS, ...)
```

Configured behavior:

* If the `mssecsvc2.0` service stops or crashes:

  * Windows **automatically restarts** the service
  * Restart delay ≈ **60 seconds**

This provides **self-healing persistence**, making the malware resistant to manual termination.

---

### 4. Filesystem Permission Modification

The following command string is embedded in the binary:

```text
icacls . /grant Everyone:F /T /C /Q
```

**Purpose:**

* Grants **full control** permissions to `Everyone`
* Applies changes **recursively**
* Continues on errors
* Suppresses output

This behavior removes filesystem permission barriers, ensuring the malware can freely encrypt or modify files.

---

### 5. Kill-Switch Mechanism

A hardcoded kill-switch domain is present:

```text
http://www.ifferfsodp9ifjaposdfj
```

Observed logic (static analysis):

* Attempts to connect to the domain using **WinINet APIs**
* **If the connection succeeds:** execution terminates
* **If the connection fails:** ransomware execution continues

This mechanism was historically used to halt widespread infections once the domain was registered.

---

### 6. Network Capability

The malware imports **WININET.dll**, indicating the ability to:

* Perform HTTP requests
* Check kill-switch availability
* Communicate outbound over the network

This confirms WannaCry is **network-aware**.

---

## Windows Application Manifest

An embedded application manifest was identified:

```xml
<requestedExecutionLevel level="asInvoker" />
```

**Key observations:**

* Does **not** explicitly request UAC elevation
* Declares compatibility with:

  * Windows Vista
  * Windows 7
  * Windows 8 / 8.1
  * Windows 10
* Uses Windows common controls (likely for ransom UI display)

---

### 7. Embedded Resource Archive (`xia_blob.bin`)

Static analysis revealed that `payload.exe` contains an **embedded password-protected ZIP archive**, commonly referred to in analyses as `xia_blob.bin`.

During execution, the malware:

* Extracts the embedded blob from its resources
* Treats it as a ZIP archive
* Decompresses it to disk using a **hardcoded password**

This archive contains **all secondary components** required for the ransomware’s operation, including executables, UI files, configuration data, and language resources.

---

### 8. ZIP Password Discovery

Using Ghidra, the ZIP password was recovered from the resource extraction routine:

```
WNcry@2ol7
```

This password is passed directly to the ZIP decompression logic and is not derived dynamically.

**Significance:**

* Confirms manual archive handling (not OS-managed)
* Allows analysts to extract all bundled components without execution
* Demonstrates a lack of advanced obfuscation for embedded resources

---

### 9. Contents of the Embedded Archive

After extraction, the following key files were identified:

#### Executables

* `taskse.exe` – Main ransomware payload (encryption, UI, Tor, payment logic)
* `taskdl.exe` – Helper/downloader component

#### UI and Resource Files

* `b.wnry` – HTML ransom note interface
* `c.wnry` – CSS stylesheet (mutated at runtime by using the unique strings for obusfication )
* `s.wnry` – JavaScript logic (timers, UI behavior) 
* `u.wnry` – Bitmap / font resources

#### Cryptographic / Configuration Data

* `r.wnry`, `t.wnry` – RSA public key material and configuration blobs

#### Language Packs

* `msg/m_*.wnry` – Ransom messages for multiple languages

These resources collectively form the ransomware’s **UI, crypto configuration, and victim interaction layer**.

---

### 10. Runtime Resource Mutation (Lightweight Polymorphism)

A function identified in Ghidra (`prepare_all_the_contents_IN_zip_file`) performs **runtime modification** of `c.wnry`.

Observed behavior:

* Reads the existing `c.wnry` file
* Randomly selects **one of three embedded strings**
* Writes the selected string back into `c.wnry`

This selection uses `rand()` and is not cryptographically secure.

* Changes file hashes between infections
* Weakly evades static signature-based detection

This is **resource-level polymorphism only** — encryption logic and payload code remain unchanged.

---

### 11. Analysis of Random-Looking Embedded Strings

strings used during resource mutation:

```
13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb
12t9YDPgwueZ9NyMgw519p7AA8isjr6S
115p7UMMngoj1pMvkpHijcRdfJNXj6Lr
```

#### Clarification: These are **NOT Bitcoin addresses**

Reasons:

* Contain invalid Base58 characters (e.g., lowercase `o`)
* Lack Base58Check checksum structure
* Do not appear in payment logic or blockchain-related code

**Conclusion:**

These strings are **random identifiers** used solely for UI/resource mutation and **have no role in cryptocurrency payments or encryption**.

---

### 12. Location of Real Bitcoin Addresses

Actual Bitcoin payment addresses were identified inside:

* `b.wnry` (HTML ransom UI)
* Referenced by JavaScript in `s.wnry`

Notably:

* Addresses are **hardcoded**
* Same addresses are reused across victims
* This design flaw allowed public tracking of ransom payments

---

### 13. Custom Encrypted Container Format

The malware uses a custom encrypted container format (`t.wnry`) identified by the **"WANACRY!"** magic header.

* The payload is decrypted entirely in memory using a dynamically derived key before execution

---

### 14. File Deletion Component (`taskdl.exe`)

`taskdl.exe` contains a file enumeration and deletion routine that iterates over files in a given drive root and deletes them, returning the count of successfully removed files.

**Technical details:**

* The implementation relies heavily on C++ STL `basic_string` internals
* This obscures the logic during static analysis but does not alter its destructive behavior

---

### 15. Session-Aware Execution (`taskse.exe`)

`taskse.exe` contains a session-aware process launcher that ensures ransomware execution across all user contexts.

**Execution requirements:**

* Requires at least one command-line argument to run

**Behavior:**

* Dynamically loads `wtsapi32.dll`
* Enumerates all active Windows Terminal Services sessions using `WTSEnumerateSessionsA`
* For each session, invokes an internal routine to execute ransomware logic within the session context
* Ensures execution across all local and remote (RDP) user sessions

**Technical implementation:**

* Enables the `SeTcbPrivilege` privilege
* Obtains a user token via `WTSQueryUserToken`
* Duplicates it into a primary token
* Creates a user environment block
* Invokes `CreateProcessAsUserA` to ensure payload execution within both local and remote (RDP) user contexts



## Updated Technical Summary

In addition to earlier findings, WannaCry:

* Bundles its full operational stack inside a password-protected ZIP resource
* Uses a hardcoded ZIP password (`WNcry@2ol7`)
* Drops and unpacks multiple executables, UI files, and language packs
* Performs lightweight UI-level polymorphism via runtime resource mutation
* Does **not** employ polymorphism in encryption or core ransomware logic
* Separates random identifiers from actual Bitcoin payment infrastructure

---

## Updated Limitations

* Analysis remains **static only**
* `taskse.exe` encryption routines not yet decompiled
* No runtime tracing or sandbox execution performed

---

## Updated Next Steps

* Decompile and analyze `taskse.exe` in depth
* Reverse AES/RSA key generation and file encryption flow
* Analyze Tor client invocation and payment confirmation logic
* Document full ransomware execution timeline

---

> This report represents the **current state of analysis** and will be expanded as additional components are reverse engineered.

---

## Final Conclusions

This static reverse engineering analysis confirms that WannaCry is a modular, multi-stage ransomware platform, not a monolithic executable. The initial `wannacry.exe` sample acts primarily as a dropper and dispatcher, while the actual ransomware functionality is distributed across multiple secondary executables and resource blobs.

**Key architectural conclusions:**

* WannaCry separates delivery, persistence, execution, UI, crypto, and networking into distinct components
* Core ransomware logic is executed from `taskse.exe`, not the original dropper
* All required components are bundled inside a password-protected ZIP archive, extracted at runtime
* The malware is designed to execute inside every active Windows user session, including RDP sessions
* UI components (`.wnry` files) are cleanly separated from encryption and network logic
* Tor is bundled locally, eliminating dependency on system-installed Tor clients
* The malware does not rely on advanced code obfuscation, packers, or virtualization-based protections

**From a defensive perspective, WannaCry's effectiveness stemmed from:**

* Aggressive worm-like propagation (not covered in this static-only report)
* Automatic privilege handling and session-wide execution
* Use of Tor to anonymize C2 communication
* Simple but effective persistence via Windows services

---

## Completeness of Analysis

At the conclusion of this analysis:

### Fully Analyzed Components

| Component | Status |
|-----------|--------|
| Dropper (`wannacry.exe`) | Fully analyzed |
| Embedded ZIP (`xia_blob.bin`) | Extracted & documented |
| ZIP password | Recovered |
| `taskse.exe` execution logic | Session & privilege logic analyzed |
| `taskdl.exe` file deletion logic | Analyzed |
| UI resources (`b.wnry`, `c.wnry`, `s.wnry`, `u.wnry`) | Identified & classified |
| Language packs (`msg/*.wnry`) | Identified |
| Tor client & DLLs | Identified |
| Onion C2 addresses | Recovered |

### Not Analyzed (Out of Scope)

* Dynamic runtime behavior
* Network traffic inspection
* AES/RSA file encryption routines
* Worm propagation via SMB (EternalBlue / DoublePulsar)
* Live payment verification behavior

These omissions are intentional and consistent with a static-only reverse engineering scope.

---

## Threat Actor Design Observations

Several design decisions are noteworthy:

* Hardcoded ZIP password indicates no intent to protect payload secrecy
* Static Bitcoin addresses reused across victims reflect poor operational security
* UI-level polymorphism only suggests evasion was not a primary concern
* Modular architecture suggests team-based development
* Use of Tor reflects moderate operational sophistication

Despite its global impact, WannaCry’s internal design is technically straightforward, relying more on exploitation and automation than advanced cryptography or obfuscation.

---

## Full WannaCry Execution Flow (Static Reconstruction)

### Stage 0: Initial Launch

**Binary:** `wannacry.exe`

* Entry point checks number of command-line arguments

### Stage 1: Kill-Switch Check

**URL:** `http://www.ifferfsodp9ifjaposdfj`

* HTTP request via WinINet
* If reachable → terminate execution
* If unreachable → continue infection

### Stage 2: Dropper Mode (argc < 2)

**Binary:** `wannacry.exe` (no arguments)

**Actions:**

* Extracts embedded ZIP (`xia_blob.bin`) from resources
* Writes payload executable to: `C:\Windows\taskche.exe`
* Executes `taskche.exe`
* Terminates original process

### Stage 3: Service Installation & Persistence

**Binary:** `taskche.exe` (service context)

**Registers Windows service:**

* Service Name: `mssecsvc2.0`
* ImagePath: `C:\Windows\taskche.exe`

**Configures service failure actions:**

* Automatic restart after ~60 seconds
* Ensures persistence across reboots

### Stage 4: Payload Unpacking

**Binary:** `taskche.exe`

**Extracts password-protected ZIP using:**

* Password: `WNcry@2ol7`

**Writes contents to working directory:**

* `taskse.exe`
* `taskdl.exe`
* `*.wnry`
* `msg\*`
* `s\Tor\*`

### Stage 5: Permission Preparation

**Command:**

```bash
icacls . /grant Everyone:F /T /C /Q
```

* Grants full filesystem access recursively
* Removes permission-based obstacles to encryption

### Stage 6: Session Enumeration

**Binary:** `taskse.exe`

* Dynamically loads `wtsapi32.dll`
* Calls: `WTSEnumerateSessionsA`

**Enumerates:**

* Local console sessions
* RDP sessions

### Stage 7: Session-Aware Execution

**For each session:**

* Enables privilege: `SeTcbPrivilege`
* Obtains user token: `WTSQueryUserToken`
* Duplicates token: `DuplicateTokenEx`
* Creates environment: `CreateEnvironmentBlock`
* Launches payload inside user session: `CreateProcessAsUserA`

**Result:** Ensures ransomware UI appears in every active session

### Stage 8: Ransomware Runtime

**Inside each user session:**

* Loads UI resources (`.wnry`)
* Displays ransom note
* Starts encryption routines (not statically analyzed here)
* Starts Tor client: `s\Tor\tor.exe`

### Stage 9: Tor & C2 Communication

**Recovered onion services:**

* `gx7ekbenv2riucmf.onion`
* `57g7spgrzlojinas.onion`
* `xxlvbrloxvriy2c5.onion`
* `76jdd2ir2embyv47.onion`
* `cwwnhwhlz52maqm7.onion`

**Used for:**

* Payment instructions
* Payment verification
* Victim tracking

### Stage 10: Cleanup & File Deletion

**Binary:** `taskdl.exe`

* Enumerates filesystem
* Deletes selected files
* Uses STL `basic_string` internally
* Returns count of deleted files

---

**End of Report**
