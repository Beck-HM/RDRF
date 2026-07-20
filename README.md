<h1>
  <img src="rdrf.ico" width="48" style="vertical-align: middle; margin-right: 12px" alt="RDRF"/>
  RDRF &mdash; Redundant Distributed Recovery File
</h1>

**Version 1.5.0** &nbsp;|&nbsp; [Build](#build) &nbsp;|&nbsp; [CLI Reference](#cli-reference) &nbsp;|&nbsp; [WPF App](#desktop-application-wpf) &nbsp;|&nbsp; [Testing](#testing)

A versioned, content-addressed backup system with block-level deduplication, fountain-code-based repair, GPU acceleration (ILGPU/CUDA), a native binary TCP protocol (`rdrf://`), and a three-node integrity architecture. Provides a cross-platform CLI, a Windows desktop (WPF) application, and a deployable storage server.

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
  - [GPU Acceleration](#gpu-acceleration)
  - [Block-Level Dedup & Versioning](#block-level-dedup--versioning)
  - [Native Protocol (`rdrf://`)](#native-protocol-rdrf)
  - [Fragment File Structure](#fragment-file-structure-on-disk-format)
- [Quick Start](#quick-start)
  - [Build](#build)
  - [CLI Examples](#cli-examples)
  - [Server Mode](#server-mode)
  - [Recovery Without Index](#recovery-without-index)
  - [Backend Transfer](#backend-transfer)
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
- (Optional) NVIDIA GPU + driver >= 470 for GPU acceleration

### Linux
- .NET 8 SDK (or use the self-contained `rdrf` binary from the tar.gz &mdash; no SDK needed)
- glibc-based distro (Ubuntu 20.04+, Debian 11+, Fedora 36+, Arch Linux, etc.)
- x64 architecture
- (Optional) NVIDIA GPU + driver >= 470 for GPU acceleration

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
| Linux x64 | `rdrf-1.5.0-pre1-linux-x64.tar.gz` &mdash; `rdrf` + plugins | ~33 MB |
| macOS Intel | `rdrf-1.5.0-pre1-osx-x64.tar.gz` &mdash; `rdrf` + plugins | ~32 MB |
| macOS ARM | `rdrf-1.5.0-pre1-osx-arm64.tar.gz` &mdash; `rdrf` + plugins | ~31 MB |

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
# Prefer -fss61 or --fss6.1 (plain -fss6.1 may be misparsed by the CLI host)
rdrf backup ~/Documents/important.pdf -fss61 -password mypass

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

Every backup is identified by a **SHA-256 fingerprint** of the raw (uncompressed) file content:

```
fingerprint = SHA256(raw_file_data)   # lowercase hex
```

- Same content &rarr; same fingerprint &rarr; automatic deduplication
- Different content &rarr; different fingerprint &rarr; new version
- Per-fragment XxHash128 is used for block-level dedup (RawFragmentHashes / DedupMap)
- Fingerprint (or -name) is the filename prefix for Index / Fragments / RC

### Three-Node Structure

Every backup produces three node types stored locally:

| Node | File Pattern | Purpose |
|------|-------------|---------|
| **Index** | `{fingerprint}.indrdrf` | Encrypted metadata: fragment layout, FSS strategy, ETN block maps, version history, salt, dedup map |
| **Fragments** | `{fingerprint}_{n}.rdrf` | Encrypted content chunks (1 MB default) with compression and FSS repair trailer |
| **RC** | `{fingerprint}.rdrc` | Recovery Container &mdash; repair data for cross-node recovery (FSS6.x only) |

Any node type can be repaired from either of the other two (FSS6.x triangle).

### FSS Strategy

| Strategy | Name | Repair | Overhead | Use Case |
|----------|------|--------|----------|----------|
| FSS1 | Neighbor | Odd and even sharded files are missing | ~100% | Quick backup, minimal CPU |
| FSS2 | Verify | Interleaved parity | ~105% | Balanced speed/reliability |
| FSS2R | Diagnose | RS(K,1) parity | ~100% | Small files, simple repair |
| FSS3 | Reed-Solomon | RS(K,M) row-column | ~33% | Moderate corruption tolerance |
| FSS5 | Cross Recovery | Cross-fragment RS | ~200% | Multi-fragment redundancy |
| FSS5+ | Seed Recovery | RS(K,K) parity-send | ~529% | Maximum redundancy |
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
- Uses Precode to ensure all source symbols are covered

**Duip Codes (FSS6.2):**
- Data-independent symbol generation with column-coverage matrix
- SIMD-accelerated (AVX2) colCoverage scan
- Higher repair capacity than LT codes

### Encryption Pipeline

```
Raw Data &rarr; SHA-256 + per-fragment XxHash128 &rarr; FSS encode &rarr; Compress
  &rarr; ETN/fountain (FSS6.x) &rarr; AES-256-CTR &rarr; Disk
```

- **Hashing:** SHA-256 whole file; XxHash128 per fragment for dedup; GPU batch hashing when NVIDIA GPU available
- **Compression:** Configurable (-c); FSS6.1/6.2 compress before ETN
- **Encryption:** AES-256-CTR (AES-NI + GPU); not GCM (ETN needs bit-level access)
- **Key derivation:** PBKDF2 600k + salt, or legacy SHA-256(password)
- **Index encryption:** Auto-detect salt-prefixed vs legacy; CBOR schema versioned
- **Zeroing:** Passwords and sensitive buffers zeroed from memory after use

### Compression

Supported compression algorithms (via `-c <algo>`):

| Algo | Library | Notes |
|------|---------|-------|
| `lz4` | K4os.Compression.LZ4 | Default; hardware-accelerated |
| `lz4hc` | K4os.Compression.LZ4 | High compression LZ4 |
| `zstd` | ZstdSharp | Fastest overall; recommended |
| `gzip` | BCL | Universal compatibility |
| `brotli` | BCL | High compression ratio |
| `lzma2` | LZMA-SDK | Maximum compression |
| `lzo` | MiniLZO | Legacy; minimal overhead |
| `xz` | Custom LZMA2 + XZ container | Standard .tar.xz format |
| `ckc` | Custom (TANS + LZ + BWT) | RDRF-native codec(No Ready yet) |

Default: `lz4`. FSS6.1/6.2 automatically skip compression to preserve ETN block alignment.

### GPU Acceleration

RDRF uses **ILGPU** (MIT license) to compile C# kernels to NVIDIA CUDA PTX at runtime. Three GPU acceleration channels:

| Channel | Target | Speedup | Threshold |
|---------|--------|---------|-----------|
| **XXH128 batch hash** | Per-fragment dedup hashing | 10-50x (64+ fragments) | Always on when GPU available |
| **AES-CTR encryption** | Fragment payload encryption | 2-10x (large payloads) | >1 MB |
| **FSS3 RS row parity** | GF(2^8) Reed-Solomon row encode | Case-by-case | Always on when GPU available |

All channels automatically fall back to CPU (AES-NI / SHA-NI / software) when no NVIDIA GPU is detected. No configuration needed &mdash; `GpuContext.IsAvailable` handles device detection at runtime.

**Requirements:** NVIDIA GPU with driver >= 470 (CUDA 11+). ILGPU handles PTX compilation &mdash; no CUDA Toolkit required.

### Block-Level Dedup & Versioning

**Dedup (content-addressable):**

```
1. Raw file split into blocks (fragment size boundary)
2. Each block hashed with XxHash128 (before compression/encryption)
3. Hash looked up in DedupMap (persisted in index)
4. Match &rarr; SourceVersion + SourceIndex reference stored
5. New &rarr; block compressed, encrypted, written as new fragment
6. DedupMap tracks RefCount per entry
7. RefCount &le; 0 entries are garbage-collected (GC mode)
8. GC never deletes fragments owned by the previous version (safe rollback)
```

**Versioning:**

- Initial backup (`-next`) creates v1
- `rdrf next` creates incremental versions
- Default mode: **Real-incremental** &mdash; each version self-contained, permanent files, independent salt
- Legacy mode (`--gc` / `-gc`): orphan cleanup, sync version history, inherited salt
- Version history stored as `VersionRecord` chain in index
- `rdrf res --ver <N>` restores any historical version

### Native Protocol (`rdrf://`)

RDRF uses a **custom binary TCP frame protocol** for backend-to-backend transfer. Compared to HTTP:

| Feature | HTTP | `rdrf://` Native |
|---------|------|-------------------|
| Header size | ~500B per request | 13B per frame |
| Concurrency | Request-response per connection | Multiplexed frames on single connection |
| Memory overhead | ~100MB (Kestrel + ASP.NET) | ~10MB (raw sockets) |
| Transfer | Chunked or full | `RESUME` frame with byte offset |

**Frame format (13 bytes):**

```
[Cmd:1B][SeqNo:4B LE][DataLen:4B LE][PathLen:4B LE][Data:N bytes]
```

**Commands:** `PUT(0x01)` `GET(0x02)` `DELETE(0x03)` `EXISTS(0x04)` `LIST(0x05)` `PING(0x06)` `RESUME(0x07)`

### Fragment File Structure (On-Disk Format)

Each fragment `{fp}_{n}.rdrf`:

```
+-------------------------------------+
| Fragment Header (6-38 bytes)        |
|   Magic: 0xFF 0x01                 |
|   Version: 1 (no salt) / 2 (salt)  |
|   Salt length (0 or 32 bytes)      |
|   CRC8 checksum of header[0..3]    |
+-------------------------------------+
| AES-256-CTR Encrypted Payload      |
|   [idxLen:4B][Embedded Index][Data]|
+-------------------------------------+
```

The Index file `{fp}.indrdrf` is CBOR-serialized with schema versioning:

```
+-------------------------------------+
| PBKDF2 Salt (variable)             |
+-------------------------------------+
| AES-256-CTR Encrypted CBOR Payload |
|   schema_version: 1                |
|   FileFingerprint, OriginalName... |
|   DedupMap, VersionRecords...      |
|   Fss6FragmentBlockMaps...         |
+-------------------------------------+
```

The embedded index in each fragment allows **index-less recovery** (`rdrf resc`).

---

## Quick Start

### Build

**Windows:**

```bash
dotnet build src/RDRF.Cli -c Release
dotnet build src/RDRF.App -c Release
dotnet build src/RDRF.Server -c Release
```

**Linux / macOS:**

```bash
dotnet publish src/RDRF.Cli -c Release -o dist --self-contained true -r linux-x64
```

### CLI Examples

```bash
# Backup
rdrf backup photo.jpg --fss6.1 -password secret -c zstd

# Incremental versioned backup
rdrf next report.docx -m "added section 3" -password secret

# Restore specific version
rdrf res abc123.indrdrf -o restored.pdf --ver 2 -password secret

# Show version history
rdrf check abc123.indrdrf -password secret

# Show per-fragment integrity (--json for machine-readable)
rdrf status abc123.indrdrf -password secret --json

# Show config
rdrf config show

# Store password securely (interactive prompt)
rdrf fp set mykey
rdrf backup photo.jpg -fp mykey

# Scan directory for backups
rdrf reach ./backups/ -password secret
```

### Server Mode

Deploy RDRF as a lightweight TCP storage server (~10MB memory):

```bash
# Start server (foreground)
rdrf server --port 8080 --path /mnt/backup-storage

# Daemon mode
rdrf server --port 8080 --path /data/storage --daemon

# With custom limits
rdrf server --port 9090 --path ./storage --limit 500 --part-timeout 12
```

Clients register the server as a remote backend:

```bash
rdrf remote add mysrv rdrf://192.168.1.100:8080
rdrf remote abc123.indrdrf -add mysrv -password secret
rdrf push abc123.indrdrf -password secret
rdrf pull abc123.indrdrf -password secret
```

The `rdrf://` protocol uses native binary framing (13B header) instead of HTTP for maximum throughput.

### Recovery Without Index

If the `.indrdrf` file is lost, fragments can still be restored from their embedded indexes:

```bash
rdrf resc ./fragments/ -o recovered.bin -password secret
```

This scans fragment headers, extracts the embedded index from fragment 0, and reconstructs the original file. Limitations: version history and FSS6.x repair data are not recoverable (stored only in the standalone index).

### Backend Transfer

Move backups between storage directories:

```bash
rdrf eti abc123.indrdrf /mnt/new-storage -password secret

# Preview without executing
rdrf eti abc123.indrdrf /mnt/new-storage --dry-run

# Keep source files
rdrf eti abc123.indrdrf /mnt/new-storage --keep-source

# Parallel transfer
rdrf eti abc123.indrdrf /mnt/new-storage --concurrency 4
```

### Desktop Application (WPF)

The Windows desktop app (`RDRF.App.exe`) provides:
- **Encrypt tab:** Select file, FSS strategy, password, start backup
- **Decrypt tab:** Load `.indrdrf`, view metadata, restore
- **History tab:** Version history, incremental backups, side-by-side diff
- **Settings:** Default output path, close behavior

### MCP Integration

MCP servers for AI tool integration (JSON-RPC 2.0 over stdio):

**Core MCP (10 tools):** `backup`, `restore`, `info`, `list`, `verify`, `check`, `next`, `status`, `config`, `reach`
**WPF MCP (5 tools):** `wpf_launch`, `wpf_backup`, `wpf_restore`, `wpf_info`, `wpf_close`

---

## CLI Reference

### Global Options

- `-password <pw>` &mdash; Supply password inline (omit for secure interactive prompt)
- `--password-file <path>` &mdash; Read password from file
- `-fp <key>` &mdash; FastPassword key (stored securely via `rdrf fp set`)
- `-?`, `-h`, `--help` &mdash; Show help

### `rdrf backup <source>`

| Option | Default | Description |
|--------|---------|-------------|
| `-o <dir>` | `./backup/` | Output directory |
| `-size <MB>` | auto | Fragment size |
| `-name <n>` | *(fingerprint)* | Custom name prefix |
| `-password <pw>` | *(prompt)* | Password |
| `-c <algo> [opts]` | `lz4` | Compression: lz4, lz4hc, zstd, gzip, brotli, lzma2, lzo, xz, ckc |
| `-fss1`&hellip;`--fss6.2` | *(required)* | FSS strategy |
| `-next` / `--next` | | Enable versioning |
| `--gc` / `-gc` | | Legacy GC mode (orphan cleanup) |
| `-m <msg>` | | Commit message (with `-next`) |
| `-fp <key>` | | FastPassword key |

### `rdrf res <indexFile>`

| Option | Default | Description |
|--------|---------|-------------|
| `-o <file>` | *(required)* | Output path |
| `--ver <N>` | *(latest)* | Version to restore |
| `-password <pw>` | *(prompt)* | Password |
| `-fp <key>` | | FastPassword key |

### `rdrf next <source>`

| Option | Description |
|--------|-------------|
| `-m <msg>` | *(required)* Commit message |
| `-o <dir>` | Storage directory |
| `-password <pw>` | Password |
| `-c <algo>` | Compression |
| `--gc` / `-gc` | Legacy GC mode |

### `rdrf server`

| Option | Default | Description |
|--------|---------|-------------|
| `--port <n>` | *(required)* | Listening port |
| `--path <dir>` | *(required)* | Fragment storage directory |
| `--limit <n>` | 1000 | Max concurrent connections |
| `--part-timeout <h>` | 24 | .part cleanup timeout hours |
| `--daemon` | | Background mode |

### `rdrf resc <fragmentsDir>`

Recover backup from fragments without index file.

| Option | Description |
|--------|-------------|
| `-o <file>` | *(required)* Output path |
| `-password <pw>` | Password |
| `-fp <key>` | FastPassword key |

### `rdrf eti <indexFile> <dstDir>`

Transfer backup between storage directories.

| Option | Description |
|--------|-------------|
| `-password <pw>` | Password |
| `-fp <key>` | FastPassword key |
| `--dry-run` | Preview only |
| `--keep-source` | Keep source files |
| `--concurrency <n>` | Parallel transfers (default: 1) |

### `rdrf push <indexFile>`

Upload fragments + RC to registered backends.

### `rdrf pull <indexFile>`

Download fragments + RC from registered backends.

### `rdrf info <indexFile>`

Show backup metadata.

### `rdrf check <indexFile>`

Show version history table.

### `rdrf verify <indexFile>`

ETN cross-validation (FSS6.x only).

### `rdrf status <indexFile>`

Per-fragment integrity. `--json` for machine-readable output.

### `rdrf diff <indexFile> <v1> <v2>`

Side-by-side version diff.

### `rdrf list <storageDir>`

List backups in directory.

### `rdrf config`

Subcommands: `show`, `set <key> <value>`, `move <new-path>`.

### `rdrf fp`

Subcommands: `set <key>`, `list`, `delete <key>`. Store passwords securely with AES-GCM encryption.

### `rdrf reach <path>`

Interactive backup scanner. Options: `-r` (recursive), `-verify`, `-info`, `-status`, `-next`, `-diff`, `-password`.

### `rdrf remote <indexFile>`

Bind/unbind backup to storage backends. `-add <names>` / `-remove <name>`.

### `rdrf remove <indexFile>`

Remove backend, purge version, or clean fragments.

### `rdrf init`

Register storage backends.

### `rdrf reset`

Update backend configuration.

---

## Project Layout

```
RDRF.NET/
├── src/
│   ├── RDRF.Core/              # Core library (encryption, FSS, compression, DSAA, GPU)
│   │   ├── Compression/        #   9 algorithms including custom XZ and CKC
│   │   ├── Device/             #   ILGPU GPU acceleration kernels
│   │   ├── FSS/                #   9 FSS strategies
│   │   ├── Storage/            #   DSAA adapter, native backend, push/pull/transfer
│   │   └── Versioning/         #   Versioned backup (real-incremental + GC mode)
│   ├── RDRF.Cli/               # Cross-platform CLI (20+ commands)
│   ├── RDRF.Server/            # Standalone TCP storage server (~10MB memory)
│   └── RDRF.App/               # Windows WPF desktop app
├── tools/
│   ├── RDRF.Mcp.Core/          # Core MCP server (10 tools)
│   ├── RDRF.Mcp.Wpf/           # WPF MCP server
│   ├── RDRF.PerfBench/         # Performance benchmark suite
│   └── RDRF.Plugins.*/         # Storage backend plugins
├── tests/
│   ├── RDRF.Core.Tests/        # 548 tests (543 pass, 3 skipped)
│   └── RDRF.Cli.Tests/         # 53 tests
└── RDRF.sln
```

---

## Storage Plugins

Backends loaded via DLL scanning from `plugins/*.dll`. The storage adapter layer (DSAA &mdash; **D**istributed **S**torage **A**dapter **A**PI) abstracts all backend operations.

| Plugin | Type | Protocol | Status |
|--------|------|----------|--------|
| PATH | `path` | Local filesystem | ✅ |
| REST | `rest` | GitHub Contents API | ✅ |
| RDRF | `rdrf` | Native binary TCP (`rdrf://`) | ✅ |
| KEY | `key` | S3-compatible | ✅ |

---

## Directory Layout (Output)

```
./backup/
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
# Core library tests (543/548 pass)
dotnet test tests/RDRF.Core.Tests -c Release

# CLI tests (53/53 pass)
dotnet test tests/RDRF.Cli.Tests -c Release
```

**Test summary:**
- Core: 543/548 pass (3 skipped: CKC BWT experimental, FSS6 cross-validation x2)
- CLI: 53/53 pass
- GPU + Server integration: 8/8 pass

---

## FAQ

### What if I forget my password?

The password is the encryption key &mdash; there is no recovery mechanism. Without it, data cannot be decrypted. **Store your password securely.** Use `rdrf fp set` for AES-GCM encrypted password storage.

### Do I need the index file?

Not necessarily. `rdrf resc` can restore from fragments alone by reading the embedded index from fragment 0. However, version history and FSS6.x repair data are only present in the standalone index. For full metadata preservation, keep the `.indrdrf` file.(Only FSS6.)

### What if a fragment is corrupted?

FSS redundant encoding provides anti-corruption capabilities. FSS6.x can detect and repair damage at the block level via ETN cross-validation. Run `rdrf status` or `rdrf verify` to check.

### Is the format versioned?

Yes. The CBOR index includes a `schema_version` field. Unknown future versions are rejected with a clear error. Current version is v1.

### What happens on crash mid-backup?

Incomplete fragments are automatically detected and cleaned. FSS6.x detects partial writes. Run `rdrf status` to check fragment integrity.

### Does RDRF support GPU acceleration?

Yes. When an NVIDIA GPU with driver >= 470 is available, XxHash128 dedup hashing, AES-CTR encryption, and FSS3 RS encoding automatically use ILGPU CUDA kernels. No configuration needed.

### Can I run RDRF as a server?

Yes. `rdrf server --port 8080 --path /data/storage` starts a lightweight TCP storage server. Clients connect via `rdrf remote add mysrv rdrf://<host>:<port>`.
