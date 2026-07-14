<h1>
  <img src="rdrf.ico" width="48" style="vertical-align: middle; margin-right: 12px" alt="RDRF"/>
  RDRF &mdash; Redundant Distributed Recovery File
</h1>

**Version 1.4.5** &nbsp;|&nbsp; [Build](#build) &nbsp;|&nbsp; [CLI Reference](#cli-reference) &nbsp;|&nbsp; [WPF App](#desktop-application-wpf) &nbsp;|&nbsp; [Testing](#testing)

A versioned, content-addressed backup system with block-level deduplication, fountain-code-based repair, and a three-node integrity architecture. Provides both a cross-platform CLI and a Windows desktop (WPF) application.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Core Principles](#core-principles)
  - [Content Addressing](#content-addressing)
  - [Three-Node Structure](#three-node-structure)
  - [FSS Strategy Family](#fss-strategy-family)
  - [ETN Block-Level Integrity](#etn-block-level-integrity)
  - [Fountain Code Repair](#fountain-code-repair)
  - [Encryption Pipeline](#encryption-pipeline)
  - [Compression](#compression)
  - [Block-Level Dedup & Versioning](#block-level-dedup--versioning)
  - [Fragment File Structure](#fragment-file-structure-on-disk-format)
- [Quick Start](#quick-start)
  - [Build](#build)
  - [CLI Examples](#cli-examples)
  - [Desktop App (WPF)](#desktop-application-wpf)
  - [MCP Integration](#mcp-integration)
- [CLI Reference](#cli-reference)
- [Project Layout](#project-layout)
- [Storage Plugins](#storage-plugins)
- [Directory Layout](#directory-layout-output)
- [Testing](#testing)
- [FAQ](#faq)

---

## Prerequisites

### Windows
- .NET 8 SDK (or run pre-built `RDRF.App.exe` single-file binary &mdash; no SDK needed)
- Windows 10/11, x64

### Linux
- .NET 8 SDK (or use the self-contained `rdrf` binary from the tar.gz &mdash; no SDK needed)
- glibc-based distro (Ubuntu 20.04+, Debian 11+, Fedora 36+, Arch Linux, etc.)
- x64 architecture

### macOS
- .NET 8 SDK (or use the self-contained `rdrf` binary from the tar.gz &mdash; no SDK needed)
- macOS 12+ (Monterey or newer), Intel or Apple Silicon

---

## Installation

### Pre-built packages

| Platform | Package | Size |
|----------|---------|------|
| Windows CLI | `rdrf.exe` + plugins | ~33 MB |
| Windows WPF | `RDRF.App.exe` &mdash; single-file, self-contained | ~157 MB |
| Linux x64 | `rdrf-1.0.0-pre1-linux-x64.tar.gz` &mdash; `rdrf` + plugins | ~33 MB |
| macOS Intel | `rdrf-1.0.0-pre1-osx-x64.tar.gz` &mdash; `rdrf` + plugins | ~32 MB |
| macOS ARM | `rdrf-1.0.0-pre1-osx-arm64.tar.gz` &mdash; `rdrf` + plugins | ~31 MB |

Extract the archive:

```bash
# Linux / macOS
tar -xzf rdrf-1.0.0-pre1-linux-x64.tar.gz
cd cli
chmod +x rdrf
rdrf --help
```

```bash
# Windows
rdrf --help
```

### First backup

```bash
# Pick a strategy (FSS6.1 recommended for integrity + repair)
rdrf backup ~/Documents/important.pdf --fss6.1 -password mypass

# Show backup metadata
rdrf info *.indrdrf -password mypass

# Restore the file
rdrf res *.indrdrf -o restored.pdf -password mypass

# Verify integrity
sha256sum ~/Documents/important.pdf restored.pdf
```

---

## Core Principles

### Content Addressing

Every backup is identified by an **XxHash128 fingerprint** computed from the raw (uncompressed) file content:

```
fingerprint = XxHash128(raw_file_data)
```

- Same content &rarr; same fingerprint &rarr; automatic deduplication
- Different content &rarr; different fingerprint &rarr; new version
- Fingerprint is used as the filename prefix for all three node types
- Content addressing enables block-level dedup: blocks within a file are hashed individually and reused across versions if unchanged

### Three-Node Structure

Every backup produces three node types stored locally:

| Node | File Pattern | Purpose |
|------|-------------|---------|
| **Index** | `{fingerprint}.indrdrf` | Encrypted metadata: fragment layout, FSS strategy, ETN block maps, version history, salt, dedup map |
| **Fragments** | `{fingerprint}_{n}.rdrf` | Encrypted content chunks (1 MB default) with LZ4 compression and FSS repair trailer |
| **RC** | `{fingerprint}.rdrc` | Recovery Container &mdash; repair data for cross-node recovery (FSS6.x only) |

Any node type can be repaired from either of the other two (FSS6.x triangle).

### FSS 

| Strategy | Name | Repair | Overhead | Use Case |
|----------|------|--------|----------|----------|
| FSS1 | Neighbor | Odd and even sharded files are missing | ~100% | Quick backup, minimal CPU |
| FSS2 | Verify | Interleaved parity | ~105% | Balanced speed/reliability |
| FSS2R | Diagnose | RS(K,1) parity | ~100% | Small files, simple repair |
| FSS3 | Reed-Solomon | RS(K,M) row-column | ~33% | Moderate corruption tolerance |
| FSS5 | Cross Recovery | Cross-fragment RS | ~200% | Multi-fragment redundancy |
| FSS5+ | Seed Recovery | RS(K,K) parity-send | ~529% | Maximum redundancy(Loco!) |
| FSS6 | ETN Verify | ETN block check | ~32% | Data integrity verification |
| FSS6.1 | ETN + LT Repair | ETN + LT fountain code | ~5% | **Recommended** &mdash; integrity + repair |
| FSS6.2 | ETN + Duip Repair | ETN + Duip fountain code | ~5% | High-corruption environments |

### ETN Block-Level Integrity

Erasure-Tolerant Node (ETN) divides each of the three node types (Index, each Fragment, RC) into **64-byte blocks**. Every block has an authentication tag stored in an ETN block map:

- Block maps are stored in the Index as flat byte arrays
- Cross-validation: Index ETN vs Fragment trailers vs RC
- Corrupted blocks are detected by hash mismatch
- Blocks can be repaired from either of the two other nodes

ETN provides **self-healing** at the block level with only ~5% storage overhead (FSS6.1/6.2).

### Fountain Code Repair

RDRF implements two fountain code algorithms for repair:

**LT Codes (FSS6.1):**
- Luby-Transform codes with Precode + Uniform degree distribution
- Efficient for up to ~50% block corruption
- Uses Precode to ensure all source symbols are covered by at least one encoding symbol

**Duip Codes (FSS6.2):**
- Data-independent symbol generation with column-coverage matrix
- SIMD-accelerated (AVX2) colCoverage scan
- Higher repair capacity than LT codes
- Suited for environments with high corruption rates

### Encryption Pipeline

```
Raw Data &rarr; XxHash128 (addressing) &rarr; LZ4 Compression &rarr; AES-256-CTR Encryption &rarr; Padded &rarr; FSS Encoding &rarr; Disk
```

- **Hashing:** XxHash128 on raw uncompressed data (for content addressing)
- **Compression:** Per-block LZ4 (~1 MB blocks) before encryption
- **Encryption:** AES-256-CTR with hardware acceleration (AES-NI)
- **Key derivation:** PBKDF2 with per-backup random salt
- **Index encryption:** Auto-detecting decrypt (legacy SHA256 or salt-based)
- **Zeroing:** Passwords are zeroed from memory after use

### Compression

LZ4 compression is applied per-block (approximately 1 MB windows) before encryption. This produces identical compression ratios to whole-file LZ4 due to the 64 KB sliding window. Compression is always enabled.

### Block-Level Dedup & Versioning

**Dedup (content-addressable):**

The dedup pipeline works at the block level across versions:

```
1. Raw file is split into blocks (aligned to fragment size boundary)
2. Each block is hashed with XxHash128 (before compression/encryption)
3. Hash is looked up in the DedupMap persisted in the index
4. If hash exists &rarr; block is a duplicate &rarr; only the reference is stored (SourceVersion + SourceIndex)
5. If hash is new &rarr; block is compressed, encrypted, and written as a new fragment
6. DedupMap entries track RefCount &mdash; how many versions reference this block
7. On version cleanup, RefCount is decremented; blocks at RefCount &le; 0 are garbage-collected
8. Garbage collection never deletes fragments owned by the previous version (safe rollback)
```

The `DedupMap` is a top-level field in the CBOR-serialized `RdrfIndex`, containing `DedupEntry` records with the original uncompressed hash and fragment location.

**Versioning (`-next` flag):**
- Initial backup creates v1
- Modified files produce incremental backups via `rdrf next`
- Each version has its own fingerprint (content-addressed)
- Version history stored as `VersionRecord` chain inside the latest index
- `CleanupOldFragments` deletes the previous version's fragments
- Old versions can still be restored via `rdrf res -v <ver>`

### Fragment File Structure (On-Disk Format)

Each fragment file `{fingerprint}_{n}.rdrf` contains an encrypted, padded byte stream:

```
+-----------------------------------------------+
| Fragment Header (4 bytes)                     |
|   Magic: 0x52 0x44 0x52 0x46 ("RDRF")        |
+-----------------------------------------------+
| Encrypted Block (variable, padded to align)   |
|   AES-256-CTR output                          |
|   LZ4-compressed raw data inside              |
|   Padded to fragment size boundary            |
+-----------------------------------------------+
| FSS6.x Repair Trailer (optional)              |
|   ETN block map (2B + 8B tiers)              |
|   Fountain code repair data                   |
|   Trailer CRC32 checksum                      |
+-----------------------------------------------+
```

The Index file `{fingerprint}.indrdrf` is CBOR-serialized and encrypted:

```
+-----------------------------------------------+
| Legacy SHA256 Salt or PBKDF2 Salt (variable)  |
+-----------------------------------------------+
| AES-256-CTR encrypted CBOR payload            |
|   RdrfIndex:                                  |
|     FileFingerprint, OriginalName, FileSize   |
|     FssStrategy, FragmentCount, CreatedAt     |
|     FragmentLevels, OriginalFragmentSizes     |
|     RawFragmentHashes (XxHash128 per block)   |
|     DedupMap (SourceIndex entries)            |
|     VersionRecords (version history chain)    |
|     Fss6FragmentBlockMaps (ETN block data)    |
|     Fss6RcBlockMap (RC ETN block data)        |
+-----------------------------------------------+
```

The RC file `{fingerprint}.rdrc` contains the recovery container with FSS6.x repair metadata, stored as encrypted CBOR.

---

## Quick Start

### Build

**Windows:**

```bash
# Full release build (CLI + WPF + LORM packages)
./build-release.ps1 -Version 1.0.0-pre1

# Or build individual projects
dotnet build src/RDRF.Cli -c Release
dotnet build src/RDRF.App -c Release
```

**Linux / macOS (CLI only):**

```bash
dotnet publish src/RDRF.Cli -c Release -o dist --self-contained true -r linux-x64
# or for macOS: -r osx-x64 / -r osx-arm64
```

### CLI Examples

```bash
# Backup with recommended strategy
rdrf backup photo.jpg --fss6.1 -password secret

# Backup with custom fragment size and versioning
rdrf backup video.mp4 --fss6.1 -size 4 -next -password secret

# Show backup metadata
rdrf info abc123.indrdrf -password secret

# Restore
rdrf res abc123.indrdrf -o restored.pdf -password secret

# Incremental backup
rdrf next report.docx -m "added section 3" -password secret

# Show version history
rdrf check abc123.indrdrf -password secret

# Verify ETN integrity (FSS6.x only)
rdrf verify abc123.indrdrf -password secret
```

### Desktop Application (WPF)

The Windows desktop app (`RDRF.App.exe`) provides a GUI:

- **Encrypt tab:** Select file, choose FSS strategy, set password, start encryption
- **Decrypt tab:** Load `.indrdrf` file, enter password, view metadata, decrypt
- **History tab:** View version history, apply incremental backups, side-by-side diff
- **Settings:** Default output path, close behavior (exit / system tray)

**CLI argument support:**

```
RDRF.App.exe "C:\path\to\backup.indrdrf"
```

Opens directly to the Decrypt tab with the index file loaded. Enable Windows file association:

```cmd
assoc .indrdrf=RDRF.Index
ftype RDRF.Index="C:\path\to\RDRF.App.exe" "%1"
```

### MCP Integration

Two MCP servers for AI tool integration (JSON-RPC 2.0 over stdio):

**WPF MCP** (5 tools): `wpf_launch`, `wpf_backup`, `wpf_restore`, `wpf_info`, `wpf_close`
**Core MCP** (7 tools): `backup`, `restore`, `info`, `list`, `verify`, `check`, `next`

Although the MCP tool has been prepared, it is still under development. Please stay tuned for the release of more plugins
---

## CLI Reference

### Global Options

- `-password <pw>` &mdash; Supply password inline (omit for secure interactive prompt)
- `-?`, `-h`, `--help` &mdash; Show help

### `rdrf backup <source>` &mdash; Backup a file

| Option | Default | Description |
|--------|---------|-------------|
| `-o <dir>` | `./backup/` | Output directory |
| `-size <MB>` | `1` | Fragment size |
| `-name <n>` | *(fingerprint)* | Custom name |
| `-password <pw>` | *(prompt)* | Password |
| `-fss1` &hellip; `--fss6.2` | *(required)* | Strategy (exactly one) |
| `-next` | | Enable versioning |
| `-node` | | Node mode to `.rdrf/` |
| `-real` | | Real incremental mode: keep all version files permanently |
| `-m <msg>` | | Commit message |

Use `--fss6.1` / `--fss6.2` on POSIX shells (single-dash with dot causes parsing issues).

### `rdrf res <indexFile>` &mdash; Restore

| Option | Default | Description |
|--------|---------|-------------|
| `-o <file>` | *(required)* | Output path |
| `-v <ver>` | *(latest)* | Version |
| `-password <pw>` | *(prompt)* | Password |

### `rdrf next <source>` &mdash; Incremental

| Option | Description |
|--------|-------------|
| `-m <msg>` | *(required)* Commit message |
| `-o <dir>` | Storage directory |
| `-password <pw>` | Password |
| `-real` | Real incremental mode: keep all version files permanently |

### `rdrf push <indexFile>` &mdash; Push to backends

Uploads fragments + RC to all registered backends via round-robin.

| Option | Description |
|--------|-------------|
| `-password <pw>` | Password |

### `rdrf pull <indexFile>` &mdash; Pull from backends

| Option | Description |
|--------|-------------|
| `-p <pw>` | Password |
| `-v list` | List available versions |
| `-v <ver>` | Version to pull (default: latest) |

### `rdrf info <indexFile>` &mdash; Metadata

Output: fingerprint, file name, size, FSS strategy, fragment count, ETN status, salt, version, timestamp.

### `rdrf check <indexFile>` &mdash; Version history

Interactive table of all versions with diff view support.

### `rdrf verify <indexFile>` &mdash; ETN cross-validation

Scans all ETN blocks (Index / Fragments / RC). Requires FSS6.x.

### `rdrf list <storageDir>` &mdash; List backups

| Option | Description |
|--------|-------------|
| `-password <pw>` | Optional (show metadata) |

### `rdrf status <indexFile>` &mdash; Per-fragment status

Shows availability and hash for each fragment.

### `rdrf diff <indexFile> <v1> <v2>` &mdash; Version diff

Side-by-side diff with syntax highlighting.

### `rdrf init` &mdash; Register backend

```bash
rdrf init -path "name:nas & base_path:/mnt/backup"
rdrf init -rest "name:gh & api_url:https://... & token:ghp_..."
```

### `rdrf remote <indexFile>` &mdash; Bind backup to backends

| Option | Description |
|--------|-------------|
| `-add <names>` | Bind backend names |
| `-remove <name>` | Unbind |
| `-password <pw>` | Password |

### `rdrf remove <indexFile>` &mdash; Remove / purge / clean

| Option | Description |
|--------|-------------|
| `-name <n>` | Remove backend from config |
| `-v <ver>` | Purge version |
| `-clean` | Delete fragments, keep index |
| `-password <pw>` | Password |

### `rdrf reset -name <n> -node` &mdash; Update backend config

---

## Project Layout

```
RDRF.NET/
├── src/
│   ├── RDRF.Core/          # Core library
│   ├── RDRF.Cli/           # Cross-platform CLI
│   └── RDRF.App/           # Windows WPF desktop app
├── tools/
│   ├── RDRF.Mcp.Core/      # Core MCP server
│   ├── RDRF.Mcp.Wpf/       # WPF MCP server
│   └── RDRF.Plugins.*/     # Storage backend plugins
├── tests/
│   ├── RDRF.Core.Tests/    # 231 tests
│   └── RDRF.Cli.Tests/     # 53 tests
├── rdrf.ico                # Application icon
├── RDRF.sln                # Solution file
└── build-release.ps1       # Release build script
```

---

## Storage Plugins

Backends loaded via DLL scanning from `plugins/*.dll`. The storage adapter layer (DSAA &mdash; **D**istributed **S**torage **A**dapter **A**PI) abstracts all backend operations.

| Plugin | Type | Status |
|--------|------|--------|
| PATH | `path` | ✅ Local / SMB / UNC |
| REST | `rest` | ✅ GitHub Contents API |
| KEY | `key` | ⏳ S3-compatible |

---

## Directory Layout (Output)

```
./rdrf/
├── rdrf_config.yaml            # Backend config
├── {fingerprint}.indrdrf       # Index (encrypted CBOR)
├── {fingerprint}.rdrc          # Recovery Container
├── {fingerprint}_0.rdrf        # Fragment 0
├── {fingerprint}_1.rdrf        # Fragment 1
└── ...
```

---

## Testing

```bash
# Core library tests (231/233 pass)
dotnet test tests/RDRF.Core.Tests -c Release

# CLI tests (53/53 pass)
dotnet test tests/RDRF.Cli.Tests -c Release
```

**Test summary:**
- Core: 231/233 pass (2 skipped &mdash; FSA multi-strategy = The FSA multi-strategy is still under development, and I have temporarily disabled it. I had to do this)
- CLI: 53/53 pass
- WPF MCP integration: 8/8 pass
- CLI integration: 7/7 pass

---

## FAQ

### What if I forget my password?

The password is the encryption key &mdash; there is no recovery mechanism. Without it, data cannot be decrypted.(Unless it is FSS6.) **Store your password in a secure location.**

RDRF focuses on **long-term archival integrity** with self-healing capabilities.

### Do I need the index file?

Yes. Without `.indrdrf`, the backup cannot be restored. **Always back up the index file separately.**(This is for version control and data security, unless you don't have these requirements)

### What if a fragment is corrupted?

The fragmented files have been processed through FSS redundant encoding and possess anti damage and recovery capabilities

### Is the format versioned?

Yes. The index contains a version number. Future RDRF versions will support reading older formats.

### What happens on crash mid-backup?

Incomplete fragments have an invalid magic header. FSS6.x detects and repairs them on restore. Run `rdrf status` to check.

---

## v1.4.5 Changelog

**WPF Desktop App**
- Passwords tab: AES-GCM encrypted key-value store with GridView UI and clipboard integration
- Key select overlay: visual dialog for picking encryption keys by fingerprint
- Theme refactor: consistent styling across all controls, WaterRipple animation
- Settings button: fixed latch behavior (not toggle), added AutomationId for UI testing
- DecryptViewModel / EncryptViewModel / PasswordViewModel / HistoryViewModel

**CLI**
- `rdrf reach`: interactive backup scanner with Spectre.Console progress bar — scan, report, verify backups
- `rdrf fp`: fingerprint command — compute and display file/content fingerprints
- `rdrf list -fp`: display fingerprints alongside backup listing
- `rdrf info --json`: machine-readable JSON output for backup metadata
- `rdrf backup` stats display + `-c` compression method/options support
- `rdrf config`: global configuration command
- 14 CLI UX improvements: restore hint, progress reporting, Spectre.Console exclusivity, cross-platform fixes

**Core Engine**
- Structured logging: `RdrfLogger` with 3 pluggable sinks (ConsoleLogSink, DebugLogSink, FileLogSink), `ILogSink` plugin architecture
- FastPassword manager: AES-GCM encrypted key-value store (`MachineKey`, `PasswordEntry`, `PasswordStore`)
- DSAA ABI native plugin system: C header bridge (`dsaa_reader.h`, `dsaa_storage.h`), `NativePluginLoader`, `NativeStorageBackend` — cross-language native plugin support
- DI container: `ServiceCollectionExtensions`, `IEncryptionLayer`, `IIndexManager` injection
- Configuration: `RdrfConfig` + `GlobalConfig` — centralized config management
- BackupPhases pipeline: `BackupReadPhase`, `RestoreFragmentReader`

**Security** (12 fixes)
- Timing attack mitigation, key leak prevention, silent error swallow elimination, log duplicate fix, CBOR deserialization size/fragment-count limits

**Performance**
- Reed-Solomon multiplication table caching
- Parallel LZ4 compression
- CBOR serialization round-trip reduction
- Sync-over-async wrappers with timeout (2h backup, 30m restore)

**Versioning**
- Git-style incremental backup: `RealVersionedBackup` / `RealVersionedRestore` — delta-only fragments based on content hash comparison
- `DssaAdapter.FindLatestIndex()` — remove `FindExistingIndex` downcast

**Testing**
- 64+ new unit tests: `LoggerTests`, `PasswordManagerTests`, `KeyStorageBackendTests` (S3 in-memory mock), `NativePluginE2ETests`, `NativePluginTests`, `RdrfConfigTests`, `FpCommandTests`, `ReachCommandTests`
- MCP WPF test protocol suite (`test_protocol.ps1`) with deterministic UI element discovery
- 15/15 UIA coverage via `test_full.ps1`
- AutomationId added to 12 WPF controls for testability

**Cleanup**
- Removed 7 large test input files (bench_doc.bin 441KB, PDFs, RFC text)
- Removed `tools/RDRF.CompressBench` (obsolete)
- 10 bug fixes: AVX2 guard, namespace consistency, UX polish, progress bar, verify command, AES limits

---
