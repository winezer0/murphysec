# MurphySec CLI · winezer0 fork

[中文](README.md) | English | [Original upstream Chinese README](https://github.com/murphysecurity/murphysec/blob/v3/README_ZH.md) | [Original upstream English README](https://github.com/murphysecurity/murphysec/blob/v3/README.md)

This project is based on [murphysecurity/murphysec](https://github.com/murphysecurity/murphysec). This fork focuses on local dependency resolution, SPDX 2.3 SBOM export, and integration with osv-scanner, while retaining the original MurphySec platform scan commands.

“Current version” here means the code in [winezer0/murphysec](https://github.com/winezer0/murphysec), not a new official upstream release. Changes below are compared with this repository's imported upstream snapshot, `f1ccb33`, and marked **[Added]**, **[Changed]**, or **[Fixed]**. The archived READMEs describe the original project.

## Contents

- [Changes from the original project](#changes-from-the-original-project)
- [Installation and quick start](#installation-and-quick-start)
- [Commands and options](#commands-and-options)
- [Usage examples](#usage-examples)
- [Ecosystems and PURLs](#ecosystems-and-purls)
- [Migration and known limitations](#migration-and-known-limitations)
- [Validation and license](#validation-and-license)

## Changes from the original project

| Type | Change | Effect / usage |
| --- | --- | --- |
| **[Added]** | `dfscan --sbom-format spdx-json`, with `spdx` as a shorthand | Export local SPDX 2.3 with PURLs for external vulnerability scanners; the existing `msdx1.1+json` format remains supported |
| **[Changed]** | The existing `sbom` command delegates to the `dfscan --sbom-format spdx-json` pipeline | Both commands share filters, warnings, and error handling; `sbom --out -` writes to stdout |
| **[Added]** | `--exclude-dev` and `--direct-only` | Filter packages and relationships in either SBOM output format |
| **[Changed]** | More ecosystem PURLs, additional SPDX metadata, `documentDescribes`, warning annotations, and stable relationship ordering | Package names no longer include their versions; missing PURL mappings are reported explicitly so an identification gap is visible |
| **[Added]** | `--maven-command` on `scan` / `dfscan` | Select a Maven executable; this option is not available on the simplified `sbom` command |
| **[Fixed]** | Forward `--no-build` to the SBOM scan task; reject `--sbom-output` without a format | Skip supported build paths; require an explicit SBOM format to avoid accidentally selecting a platform scan |
| **[Fixed]** | Inspector failures are surfaced; scan strategies serialize their actual values | Local inspector failures produce stderr diagnostics and a nonzero exit code, while preserving a partial SBOM where possible; degradation warnings are included in the output |
| **[Fixed]** | Maven dependency identity includes type/classifier; corrected scope traversal, default local repository, and parent POM `relativePath` resolution | Reduce incorrect merges, library development dependencies, and missing runtime transitives; use `~/.m2/repository` when settings omit `localRepository` |
| **[Added]** | Active project profiles in Maven static resolution | Merge profile properties, dependencyManagement, and dependencies; handle explicit `-P`, default, JDK, OS, property, and file activation, with warnings for unresolved conditions |
| **[Fixed]** | Go `replace`, preferred `vendor/modules.txt` input, and module root/direct dependency edges | Report replacement identities/versions, use vendored module inventories, and retain direct dependency relationships in the Go SBOM |
| **[Fixed]** | Standalone npm v1/v2/v3 `package-lock.json`, workspace graphs, installation locations, and development flags | Scan without root/member `package.json` files, preserve distinct transitive versions, and report malformed lockfiles or missing required references |
| **[Fixed]** | R / renv ecosystem corrected from `spm` to `cran` | Emit `pkg:cran/...` rather than identifying R packages as Swift packages |
| **[Changed]** | Fork build/release workflow; removal of some inherited workflows and issue templates | Build Linux / macOS / Windows amd64 and arm64 artifacts with `SHA256SUMS`; check this fork's Releases for available builds |

See the [CLI](cmd/murphy/internal/scan/), [SPDX formatter](inspector/textual_formatter.go), [Maven](module/maven/), [Go](module/go_mod/), [npm](module/npm/), and [release workflow](.github/workflows/build.yml) implementations.

## Installation and quick start

### Install this fork

Choose a suitable build from [winezer0/murphysec Releases](https://github.com/winezer0/murphysec/releases). Build from source if there is no suitable release or you need changes in the current source. The upstream installers and Releases linked in the archived READMEs do not guarantee these fork changes.

Source builds require Git and **Go 1.24.0 or later**, as specified in [go.mod](go.mod).

Linux / macOS:

```bash
git clone https://github.com/winezer0/murphysec.git
cd murphysec
go build -o murphysec .
./murphysec --version
./murphysec --help
```

Windows PowerShell:

```powershell
git clone https://github.com/winezer0/murphysec.git
Set-Location murphysec
go build -o murphysec.exe .
.\murphysec.exe --version
.\murphysec.exe --help
```

The examples below assume `murphysec` is on `PATH`; otherwise use `./murphysec` or `.\murphysec.exe`. Build-based scans need ecosystem tools such as Maven/JDK, Go, or npm. Static resolution still needs sufficient manifests, lockfiles, or cached dependencies.

### Export your first local SBOM

```bash
murphysec sbom /path/to/project --no-build --out project.spdx.json
```

This command needs no token, calls no MurphySec platform API, and does not upload the project. It produces a dependency inventory; **it does not query vulnerabilities itself**. Use osv-scanner or a platform scan for vulnerability results.

Local export without platform API calls does not guarantee a disconnected run: package managers may run by default, and `--no-build` skips supported build paths but resolution can still read caches or contact package repositories. Prepare dependency data and inspect warnings before relying on a scan in an isolated network.

## Commands and options

| Command | Purpose | MurphySec platform API / token |
| --- | --- | --- |
| `sbom <DIR>` | Export local SPDX 2.3; default output is `spdx.json` in the working directory | No / not required |
| `dfscan <DIR> --sbom-format spdx-json` | Export local SPDX with additional Maven options; default output is stdout | No / not required |
| `dfscan <DIR> --sbom-format msdx1.1+json` | Export the existing private format locally; default output is stdout | No / not required |
| `dfscan <DIR>` without `--sbom-format` | Dependency-based platform scan | Yes / required |
| `scan <DIR>` | Original platform scan entry point; can upload project directory files | Yes / required |

Common options for local export follow. Each command's `--help` is the full reference.

| Option | Commands | Meaning |
| --- | --- | --- |
| `--out <FILE>` | `sbom` | Defaults to `spdx.json`; `-` selects stdout |
| `--sbom-format <FORMAT>` | `dfscan` | `spdx-json` / `spdx` / `msdx1.1+json`; explicitly selects local SBOM export |
| `--sbom-output <FILE>` | `dfscan` | Defaults to `-`; requires `--sbom-format` |
| `--no-build` | `sbom` / `dfscan` / `scan` | Skip supported build paths; completeness depends on available dependency data |
| `--exclude-dev` **[Added]** | `sbom` / SBOM output from `dfscan` | Remove dependencies marked as non-runtime, including Maven test/provided/system and npm dev |
| `--direct-only` **[Added]** | `sbom` / SBOM output from `dfscan` | Keep only direct dependencies; can be combined with `--exclude-dev` |
| `--maven-command <PATH>` **[Added]** | `dfscan` / `scan` | Select the Maven executable |
| `--maven-settings <FILE>` | `dfscan` | Select a Maven settings file |
| `--maven-arg=<ARG>` / `--maven-prepend-arg=<ARG>` | `dfscan` / `scan` | Append / prepend one Maven argument; repeat as needed and use `=` for values starting with `-` |
| `--no-log-file` / `--log-level debug` | Global | Disable log files / enable diagnostic logging |

Create output directories first. Existing output files are overwritten. The two dependency filters affect the exported graph; they do not exclude filesystem directories.

## Usage examples

### Local SPDX and the original format

```bash
# Simplified entry point; shares the SPDX pipeline with the next command
murphysec sbom /path/to/project --no-build --out project.spdx.json

# Full option set
murphysec dfscan /path/to/project --no-build --sbom-format spdx-json --sbom-output project.spdx.json

# Original private format: modules, scan_warnings_codes, etc.
murphysec dfscan /path/to/project --no-build --sbom-format msdx1.1+json --sbom-output project.msdx.json

# stdout; sbom --out - also works
murphysec dfscan /path/to/project --no-build --sbom-format spdx-json --sbom-output -

# Runtime direct dependencies only
murphysec sbom /path/to/project --no-build --exclude-dev --direct-only --out runtime-direct.spdx.json
```

### Maven options and profiles

```bash
# Build-based scan: custom Maven and settings; may download plugins/dependencies
murphysec dfscan /path/to/java-project --sbom-format spdx-json --sbom-output java.spdx.json --maven-command /opt/apache-maven/bin/mvn --maven-settings /path/to/settings.xml

# [Added] Static resolution: explicitly activate prod and supply a property
murphysec dfscan /path/to/java-project --no-build --sbom-format spdx-json --sbom-output java-prod.spdx.json --maven-arg=-Pprod --maven-arg=-Denv=prod
```

Use `dfscan` for these Maven-specific options; `sbom` exposes only the simplified export options. **[Added]** Static resolution merges dependencies, dependency management, and properties from active project profiles. Unresolved activation conditions generate warnings. See the build-based profile limitation below.

### Standalone npm lockfiles and Go vendor projects

**[Fixed]** The scan argument remains a directory. An npm directory can contain only `package-lock.json`; there is no need to fabricate `package.json`.

```bash
murphysec sbom /path/to/lockfile-directory --no-build --out npm.spdx.json
murphysec sbom /path/to/vendored-go-project --no-build --out go.spdx.json
```

lockfileVersion 1/2/3 are supported; v2/v3 retain workspace, installation location, and nested dependency information. Go prefers a readable `vendor/modules.txt` inventory when present and uses `go.mod` to classify direct and indirect dependencies.

### Use with osv-scanner

MurphySec resolves dependencies and exports the SBOM; osv-scanner matches vulnerabilities. With OSV-Scanner v2 installed, use the following flow. Keep the `.spdx.json` suffix for SPDX detection; see the [official OSV SBOM documentation](https://google.github.io/osv-scanner/usage/scan-source).

```bash
murphysec sbom /path/to/project --no-build --out project.spdx.json
osv-scanner scan source --lockfile project.spdx.json --format json --output-file osv-results.json
```

The second command uses online vulnerability services by default. For offline matching, prepare a local database following the [official OSV offline instructions](https://google.github.io/osv-scanner/usage/offline-mode/) and use its `--offline` mode. A generated PURL does not guarantee that a vulnerability database covers its ecosystem or version.

The repository includes parser compatibility tests and fixed offline vulnerability fixtures. See the [compatibility record](OSV_SCANNER_COMPATIBILITY.md) for coverage; it does not establish complete dependency graphs for every possible input.

### Original platform scans

```bash
murphysec auth login
murphysec dfscan /path/to/project --json
murphysec scan /path/to/project --json
```

Log in with a MurphySec platform access token, or authenticate with `--token <TOKEN>`. Without a SBOM format, `dfscan` submits dependency data and queries the platform. Standard `scan` uploads directory files; modes such as `dfscan --deep` can also upload files. Choose the appropriate mode; the archived upload description is not a substitute for the current command behavior.

## Ecosystems and PURLs

Current inspectors include Maven, Gradle, Ivy, SBT, npm, Yarn, pnpm, Go, Python / Poetry, NuGet, Composer, Cargo, Bundler, Pub, CocoaPods, Conan, LuaRocks, Perl, rebar3, R / renv, and ArkTS / ohpm. Support depends on the input format and tool environment; the existence of an inspector is not a claim that all projects have been validated.

**[Changed]** SPDX ecosystem-to-PURL-type mappings:

| ecosystem | PURL type |
| --- | --- |
| `maven` / `npm` / `pypi` / `nuget` | Same name |
| `go` / `bundler` / `pubspec` / `composer` | `golang` / `gem` / `pub` / `composer` |
| `cargo` / `conan` / `cocoapods` / `luarocks` | Same name |
| `cran` / `hex` / `rebar` / `perl` / `spm` | `cran` / `hex` / `hex` / `cpan` / `swift` |

`spm → swift` is an output mapping, not a newly added Swift project inspector. R / renv now emits `cran`. Packages from unmapped ecosystems such as `ohpm` can remain in the inventory without a fabricated PURL; an SPDX annotation reports the matching gap.

## Migration and known limitations

| Previous usage / scenario | Current behavior and guidance |
| --- | --- |
| `dfscan DIR --sbom-output out.json` | **[Changed]** Fails without `--sbom-format`; use `--sbom-format spdx-json --sbom-output out.spdx.json` or explicitly choose msdx |
| `sbom DIR --out out.json` | Still supported; **[Changed]** uses the shared pipeline and accepts filters; prefer `.spdx.json` when passing output to OSV |
| `sbom --type ...` | The old hidden `--type` option has been removed; the format is fixed to SPDX JSON |
| Expecting local SBOM output from `--json` | `--json` controls platform result presentation; use `sbom` or `dfscan --sbom-format ...` for local export |
| Nonzero local scan exit with an existing SBOM | **[Changed]** Inspector failures may leave partial results; inspect stderr, SPDX `annotations`, or msdx `scan_warnings_codes` rather than treating file existence as success |
| Exit code 0 after degraded resolution | Warnings such as `mvn_not_found`, `mvn_failed`, or `mvn_profile_activation_unknown` may still exist; automation should inspect output warnings too |
| Maven build-based profiles | All collected profile IDs are still passed to Maven `-P`, potentially activating profiles that should be inactive; consider `--no-build` static resolution for activation-aware analysis and inspect the result |
| Go static / vendor graphs | Direct/indirect classification is available, but not every transitive edge; local directory replacements retain the original require identity/version and cannot describe local edits; static `exclude` matches warn without recomputing MVS |
| npm v1 standalone lockfile | Without the manifest, top-level lock entries are the starting points; original direct/transitive relationships cannot be guaranteed |
| Development dependency filtering | Depends on inspector flags; unmarked dependencies are retained, so this cannot prove the exact contents of a deployment |

## Validation and license

Regression tests cover Maven profiles, Go replace/vendor, npm lockfiles/graphs, SPDX formatting, and warnings. Run the regular suite with:

```bash
go test ./...
```

OSV integration tests additionally require `OSV_SCANNER`; they are skipped when unset. See [OSV_SCANNER_COMPATIBILITY.md](OSV_SCANNER_COMPATIBILITY.md) for commands, verified inputs, and the distinction between online tests and offline fixtures.

Licensed under the [Apache License 2.0](LICENSE), retaining the original project's copyright and license notices. See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidance.
