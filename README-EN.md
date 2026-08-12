# JavaArchitectureAnalysisTool

A command-line tool for analyzing the internal structure of Java jar packages, focusing on identifying the platforms and CPU architectures supported by C/C++ native libraries (.so / .dylib / .dll / .a / .jnilib / .lib) embedded in jars. Helps determine whether a jar can run on target platforms (e.g., ARM Linux, Apple Silicon macOS).

## Features

- **`jar` subcommand**: Scans native binary artifacts inside jars, identifies formats (ELF / Mach-O / PE / XCOFF / Archive) and CPU architectures (x86_64 / aarch64 / riscv64 / loongarch64 / s390x / ppc64, etc.), and analyzes architecture coverage gaps per platform with normalization
- **`pom` subcommand**: Parses Maven's pom.xml, outputs complete transitive dependency tree and dependency relationship graph
- **`overlay` subcommand**: Generates native library overlay plans based on the `java.library.path` mechanism to prioritize external library loading, skipping same-named libraries inside jars (for adding architectures, changing versions, fixing vulnerabilities, etc.)

## Supported Jar Packaging Formats

| Packaging Format | Typical Extension | Supported |
|------------------|-------------------|:---------:|
| maven-assembly `with-dependencies` (flat) | `.jar` | ✅ |
| Spring Boot Executable jar (nested `BOOT-INF/lib/*.jar`) | `.jar` | ✅ |
| WAR package (`WEB-INF/lib/*.jar`) | `.war` | ✅ |
| EAR package (`lib/*.jar`) | `.ear` | ✅ |
| Hadoop/Spark tar distribution lib directory | directory | ✅ |
| Maven local repository directory | directory | ✅ |

The `jar` subcommand recursively scans all `.jar` files when given a directory, merging results; nested jars inside each jar are also recursively scanned (max nesting depth 5, single nested jar limited to 200MB, to prevent zip bombs).

## Installation

Use precompiled binaries directly (see `dist/` directory), or build from source:

```bash
go build -trimpath -ldflags "-s -w" -o JavaArchitectureAnalysisTool .
```

Or use the `build.sh` script to build all platforms at once:

```bash
./build.sh              # Build all platforms to dist/
./build.sh current      # Build current platform only
./build.sh linux        # Build Linux only (amd64 + arm64)
./build.sh windows      # Build Windows only (amd64)
./build.sh darwin       # Build macOS only (incl. universal)
./build.sh clean        # Clean dist/
```

Cross-platform manual compilation:

```bash
# Linux x86_64
GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o JavaArchitectureAnalysisTool-linux-amd64 .
# Linux aarch64
GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o JavaArchitectureAnalysisTool-linux-arm64 .
# Windows x86_64
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o JavaArchitectureAnalysisTool-windows-amd64.exe .
# macOS x86_64
GOOS=darwin  GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o JavaArchitectureAnalysisTool-darwin-amd64 .
# macOS arm64 (Apple Silicon)
GOOS=darwin  GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o JavaArchitectureAnalysisTool-darwin-arm64 .
# macOS Universal Binary (must be executed on macOS)
lipo -create -output JavaArchitectureAnalysisTool-darwin-universal \
    JavaArchitectureAnalysisTool-darwin-amd64 \
    JavaArchitectureAnalysisTool-darwin-arm64
```

No Go runtime required on the target machine; binaries are statically linked.

## Usage Guide

### 1. `jar` Subcommand — Analyze Native Architecture Artifacts

```bash
# Single jar
JavaArchitectureAnalysisTool jar /path/to/app.jar

# All jars in a directory (Hadoop lib / Maven repo, etc.)
JavaArchitectureAnalysisTool jar /opt/hadoop/share/hadoop/common/lib/

# Offline mode, no Maven Central access (architecture scanning itself doesn't use network; only library identification is offline)
JavaArchitectureAnalysisTool jar -offline /path/to/app.jar

# English output
JavaArchitectureAnalysisTool jar -lang en /path/to/app.jar

# Mixed parameter order (positional args before or after flags)
JavaArchitectureAnalysisTool jar /path/to/app.jar -offline -lang en
```

**Parameters**:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-offline` | `false` | Offline mode, skips Maven Central queries, relies only on jar-embedded metadata for library identification |
| `-lang` | Auto-detect | Output language: `zh` / `en` (auto-detects from system `LANG` environment variable) |

**Output Contents**:

- **C/C++ native artifact list**: Lists each native library file inside the jar, annotating format, architecture, file size, and source path
- **Architecture support overview by platform**: Lists supported architecture sets per platform (Linux / macOS / Windows / AIX)
- **Architecture gap analysis**: Relative to the complete architecture set of other libraries on the same platform, identifies which architectures a library is missing (uses normalized library names to merge files of the same library with different architectures, e.g., `libsnappyjava.dylib` + `libsnappyjava.jnilib` are merged)
- **Dependency library list**: Printed grouped by jar file path; title printed only once to avoid repetition

**Architecture Identification Capabilities**:

| Format | Supported Architectures |
|--------|------------------------|
| ELF (Linux/BSD) | x86_64, i386, aarch64, arm, armv7, riscv64, riscv32, loongarch64, loongarch32, mips, mips64, ppc, ppc64, s390, s390x, sparc, sparc64, ia64 |
| Mach-O (macOS/iOS) | x86_64, i386, arm64, armv7; supports Fat/Universal Binary (one file with multiple slices, deduplicated) |
| PE (Windows) | x86_64 (AMD64), x86 (i386), ia64 |
| XCOFF (AIX) | ppc, ppc64 |
| Archive (.a / .lib) | Recursively parses internal members, supports GNU ar and BSD ar formats, infers architecture from internal member formats (ELF/Mach-O) |

### 2. `pom` Subcommand — Parse Maven Dependency Tree

```bash
# Offline mode (default), using only local ~/.m2/repository
JavaArchitectureAnalysisTool pom pom.xml

# Allow Maven Central access to fetch missing transitive dependency poms
JavaArchitectureAnalysisTool pom -offline=false pom.xml

# Specify private repository
JavaArchitectureAnalysisTool pom -remote=https://my.repo/maven2/ pom.xml

# English output
JavaArchitectureAnalysisTool pom -lang en pom.xml
```

**Parameters**:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-offline` | `true` | Use only local `~/.m2/repository`, no remote Maven Central access |
| `-remote` | — | Remote repository URL (only effective when `-offline=false`, defaults to Maven Central) |
| `-lang` | Auto-detect | Output language: `zh` / `en` (auto-detects from system `LANG` environment variable) |

Outputs complete transitive dependency list and `ID → DependsOn` dependency relationship graph.

### 3. `overlay` Subcommand — Native Library Overlay Plan

**Principle**: When the JVM loads native libraries, it searches the directory specified by `-Djava.library.path` first; once a file with the same name is found, it won't extract from inside the jar. By placing required native libraries in an external directory, you can skip same-named libraries inside the jar, achieving architecture supplementation, version changes, vulnerability fixes, etc., completely non-intrusively to the jar itself.

```bash
# Basic usage: analysis only, print suggestions and download URLs
JavaArchitectureAnalysisTool overlay /path/to/app.jar

# Specify target platform/architecture
JavaArchitectureAnalysisTool overlay app.jar -os linux -arch aarch64

# Specify macOS ARM (Apple Silicon) target
JavaArchitectureAnalysisTool overlay app.jar -os darwin -arch arm64

# Specify Windows x86_64 target
JavaArchitectureAnalysisTool overlay app.jar -os windows -arch x86_64

# Default download: without -mirror, automatically downloads jar from Maven repo and extracts .so
JavaArchitectureAnalysisTool overlay app.jar -os linux -arch aarch64 -download

# Specify existing local libraries + mirror URL template + actual download
JavaArchitectureAnalysisTool overlay app.jar \
    -local libsnappyjava.so=/opt/libs/libsnappyjava.so \
    -mirror https://mirrors.example.com/native/{lib}/{os}/{arch}/{libfile} \
    -download -outdir /opt/app-native-libs

# Specify multiple local libraries + set download timeout
JavaArchitectureAnalysisTool overlay app.jar \
    -local libsnappyjava.so=/opt/libs/libsnappyjava.so \
    -local libzstd-jni.so=/opt/libs/libzstd-jni.so \
    -download -timeout 120 -outdir /opt/app-native-libs

# English output
JavaArchitectureAnalysisTool overlay app.jar -lang en -os linux -arch aarch64 -download

# Mixed parameter order (positional args before or after flags)
JavaArchitectureAnalysisTool overlay -os linux -arch aarch64 app.jar -download
```

**Parameter Description**:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-os` | Current system | Target OS: `linux` / `darwin` / `windows` / `aix` |
| `-arch` | Current architecture | Target architecture: `x86_64` / `aarch64` / `arm64` / `arm` / `riscv64`, etc. |
| `-outdir` | `./native-overlay` | External library output directory |
| `-local` | — | Specify a local file for a library, format `libname=path`, can be repeated |
| `-mirror` | — | Mirror URL template, placeholders: `{lib}` `{libfile}` `{os}` `{arch}` |
| `-download` | `false` | Actually download missing libraries (default: only print URLs) |
| `-timeout` | `60` | Download timeout in seconds |
| `-lang` | Auto-detect | Output language: `zh` / `en` (auto-detects from system `LANG` environment variable) |

**Native Library Source Priority**:

1. `-local` specified local file → copied to outdir (size compared with same-named file in jar; difference >2× triggers warning)
2. Same-named file already in outdir → skipped
3. `-mirror` specified → uses user-specified mirror template to generate direct `.so` download URL; with `-download`, actually downloads
4. No `-mirror` specified → automatically extracts Maven coordinates from nested jar's `pom.properties`, downloads the jar for the target architecture from Maven repository, then extracts `.so` file from it

**Maven Repository Download Flow** (executed automatically when `-mirror` is not specified):

1. During jar scanning, reads each nested jar's `META-INF/maven/*/pom.properties` to extract `groupId:artifactId:version`
2. Extracts classifier from the original jar filename (e.g., `netty-transport-native-epoll-4.1.128.Final-linux-x86_64.jar` → `linux-x86_64`)
3. Replaces architecture keywords in the classifier with the target architecture, generating multiple candidates (compatible with different naming conventions):
   - `x86_64` → `aarch_64` (netty convention) / `aarch64` (generic) / `arm64` (Apple convention)
4. Constructs jar download URLs for each candidate classifier × each mirror source, tries them in order
5. After downloading the jar, opens the zip, iterates entries to find the `.so` file matching the target architecture, extracts to outdir

**Maven Mirror Source List** (sorted by priority, China mirrors first):

| # | Mirror | Base URL |
|:-:|--------|----------|
| 1 | Alibaba Cloud | `https://maven.aliyun.com/repository/central` |
| 2 | Huawei Cloud | `https://repo.huaweicloud.com/repository/maven-central` |
| 3 | Tencent Cloud | `https://mirrors.cloud.tencent.com/nexus/repository/maven-public` |
| 4 | Maven Central | `https://repo1.maven.org/maven2` |
| 5 | Maven Central (backup) | `https://repo.maven.apache.org/maven2` |

Download URL format: `{base}/{groupIdPath}/{artifactId}/{version}/{artifactId}-{version}-{classifier}.jar`

**URL Template Placeholders**:

| Placeholder | Meaning | Example |
|-------------|---------|---------|
| `{lib}` | Library root name (without version, without extension) | `libsnappyjava` |
| `{libfile}` | Actual filename | `libsnappyjava.so` |
| `{os}` | Target OS | `linux` |
| `{arch}` | Target architecture | `aarch64` |

Example template: `https://mirrors.example.com/native/{lib}/{os}/{arch}/{libfile}`

**Java startup parameter suggestion is provided at the end of output**:

```
java -Djava.library.path=/opt/app-native-libs -jar /path/to/app.jar
```

## Output Conventions

- **Format names with descriptions**: `ELF (Linux/BSD executable)`, `Mach-O (macOS/iOS executable)`, `PE (Windows executable)`, `XCOFF (AIX executable)`, `Archive(.a) (Unix static library)`
- **Architecture names with descriptions** (in detailed list): `x86_64 (Intel 64-bit)`, `aarch64 (ARM 64-bit)`, `riscv64 (RISC-V 64-bit)`, `loongarch64 (LoongArch 64-bit)`, etc.
- **Overview/statistics use short form**: `[i386, x86_64]`, avoiding lengthy descriptions cluttering the output
- **Detailed file list uses full descriptions**: `arch=x86_64 (Intel 64-bit) + arm64 (ARM 64-bit)`, ensuring readability
- **Progress to stderr, results to stdout**: Supports `> result.txt` to redirect clean results to a file
- **Path masking**: User home directory in output is automatically replaced with `~` to hide account info

## Internationalization (i18n)

The tool supports Chinese and English output, auto-detecting from the system `LANG` environment variable by default (falls back to Chinese on detection failure):

```bash
# Auto-detect (default)
JavaArchitectureAnalysisTool jar app.jar

# Force English
JavaArchitectureAnalysisTool jar app.jar -lang en

# Force Chinese
JavaArchitectureAnalysisTool jar app.jar -lang zh

# Via environment variable
LANG=en_US.UTF-8 JavaArchitectureAnalysisTool jar app.jar
```

All subcommands (`pom`, `jar`, `overlay`) support the `-lang` parameter.

## Normalization Rules

To avoid the same library being misjudged as different libraries due to filename differences (extensions, architecture keywords, platform keywords), `normalizeLibraryName` will:

1. **Unify extensions**: `.jnilib` → `.dylib` (both are macOS dynamic libraries)
2. **Remove architecture keywords**: `aarch_64` / `aarch64` / `aarch_` / `x86_64` / `x86_` / `x86` / `arm64` / `amd64` / `riscv64` / `loongarch64` / `sparc64` / `ppc64` / `s390x` / `mips64` / `i386` / `i686` / `_64` / `_32` / `64` / `32`, etc.
3. **Remove platform keywords**: `linux` / `windows` / `win32` / `win64` / `win` / `macosx` / `darwin` / `osx` / `mac` / `sunos` / `aix`
4. **Clean up extra separators**: Merge consecutive `_`, trim leading/trailing `_-.`

Examples:
- `libsnappyjava.dylib` + `libsnappyjava.jnilib` → `libsnappyjava.dylib`
- `netty_tcnative_osx_.jnilib` + `netty_tcnative_osx_aarch_.jnilib` → `netty_tcnative.dylib`
- `jline32.dll` + `jline64.dll` → `jline.dll`

## Cross-Platform Support Matrix

| Platform | Architecture | Precompiled Binary |
|----------|--------------|-------------------|
| Linux | x86_64 | `JavaArchitectureAnalysisTool-linux-amd64` |
| Linux | aarch64 (ARM) | `JavaArchitectureAnalysisTool-linux-arm64` |
| Windows | x86_64 | `JavaArchitectureAnalysisTool-windows-amd64.exe` |
| macOS | x86_64 (Intel) | `JavaArchitectureAnalysisTool-darwin-amd64` |
| macOS | arm64 (Apple Silicon) | `JavaArchitectureAnalysisTool-darwin-arm64` |
| macOS | Universal | `JavaArchitectureAnalysisTool-darwin-universal` |

All Linux binaries are statically linked; no additional runtime required on target machines.

## Notes

1. **`jar -offline` only affects library identification**: Architecture scanning itself doesn't use the network; `-offline=true` only prevents `go-dep-parser` from querying Maven Central for jar GAV coordinates
2. **overlay does not modify the original jar**: All external libraries are placed in a separate directory, specified via `-Djava.library.path`, completely non-intrusive to the original jar
3. **`-local` specified local files undergo size validation**: If the size difference with the same-named file in the jar exceeds 2×, a warning is issued prompting version verification
4. **Downloads use atomic writes**: Writes to `.part` temporary file first, then renames on completion, avoiding half-written files polluting the output directory due to HTTP interruptions
5. **Nested jar recursion has safeguards**: Max depth 5, single nested jar limited to 200MB, preventing zip bombs
6. **Mixed parameter order supported**: All subcommands support `app.jar -flag` and `-flag app.jar` mixed order (manually reorders Go flag's positional argument limitation)
7. **Maven download downloads jar then extracts**: When `-mirror` is not specified, the tool downloads the jar for the target architecture from Maven repository, then extracts the `.so` file from it (Maven repositories don't store `.so` files directly)
8. **Path masking**: User home directory in output is automatically replaced with `~` to hide sensitive account info
9. **Downloaded files undergo architecture validation**: After download, file headers are scanned to confirm format and architecture match the target
