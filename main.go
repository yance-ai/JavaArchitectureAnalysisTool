package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	stdlog "log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/aquasecurity/go-dep-parser/pkg/java/jar"
	"github.com/aquasecurity/go-dep-parser/pkg/java/jar/sonatype"
	"github.com/aquasecurity/go-dep-parser/pkg/java/pom"
	deplog "github.com/aquasecurity/go-dep-parser/pkg/log"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"go.uber.org/zap"
)

// MavenCoord Maven 坐标,用于从 Maven 仓库下载 jar 包 / Maven coordinates, used to download jars from Maven repositories
type MavenCoord struct {
	GroupID    string
	ArtifactID string
	Version    string
}

// NativeArtifact 描述 jar 包内发现的 C/C++ 本地二进制产物 / Describes C/C++ native binary artifacts found inside a jar
type NativeArtifact struct {
	Path     string // jar 内的相对路径,例如 lib/linux-x86_64/libfoo.so / Relative path inside the jar, e.g. lib/linux-x86_64/libfoo.so
	FileSize int64
	Format   string   // "Mach-O" | "ELF" | "PE" | "Archive(.a)" | "XCOFF" | "Unknown"
	Archs    []string // 对应的 CPU 架构列表,一个 Fat Mach-O 可能包含多个 / Corresponding CPU architecture list, a Fat Mach-O may contain multiple
	Platform string   // 推测的平台: macOS / Linux / Windows / 未知 / Inferred platform: macOS / Linux / Windows / Unknown
	// 来源 jar 的 Maven 坐标 (从嵌套 jar 的 META-INF/maven/.../pom.properties 提取) / Source jar Maven coordinates (extracted from nested jar's META-INF/maven/.../pom.properties)
	// 用于 overlay 下载:根据坐标和目标架构下载对应 jar,再从中提取 .so / Used for overlay download: download the corresponding jar based on coordinates and target architecture, then extract .so from it
	SourceCoord   MavenCoord
	SourceJarName string // 来源 jar 文件名 (内层 jar,如 netty-transport-native-epoll-4.1.128.Final-linux-x86_64.jar) / Source jar filename (inner jar, e.g. netty-transport-native-epoll-4.1.128.Final-linux-x86_64.jar)
}

// ScanResult jar 包附加的结构扫描结果 / ScanResult additional structural scan results of the jar
type ScanResult struct {
	HasNative   bool
	NativeCount int
	Platforms   []string // 去重后的平台集合 / Deduplicated platform set
	Archs       []string // 去重后的架构集合 / Deduplicated architecture set
	Artifacts   []NativeArtifact
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	// 静默 go-dep-parser 内部日志,避免解析过程中刷屏 / Silence go-dep-parser internal logs to avoid flooding during parsing
	nop := zap.NewNop()
	defer nop.Sync()
	deplog.SetLogger(nop.Sugar())
	SetLang(detectLang())

	switch os.Args[1] {
	case "pom":
		runPom(os.Args[2:])
	case "jar":
		runJar(os.Args[2:])
	case "overlay":
		runOverlay(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "%s\n\n", T("unknown_cmd", os.Args[1]))
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `用法:
  JavaArchitectureAnalysisTool pom <pom.xml路径>           解析 Maven 的 pom.xml
  JavaArchitectureAnalysisTool jar <jar文件或目录路径>     解析 .jar 文件 (识别 C/C++ 本地架构产物)
                                                            传目录时会递归扫描所有 .jar,合并结果
  JavaArchitectureAnalysisTool overlay <jar文件路径>       生成本地库覆盖方案 (java.library.path)
                                                            优先加载外部 .so/.dylib/.dll,跳过 jar 内同名库
  JavaArchitectureAnalysisTool help                        显示此帮助信息

overlay 可选参数:
  -os <linux|darwin|windows|...>   目标操作系统 (默认: 当前系统)
  -arch <x86_64|aarch64|arm64|...> 目标 CPU 架构 (默认: 当前架构)
  -outdir <path>                   外部库输出目录 (默认: ./native-overlay)
  -local <libname=path>            指定某个本地库的本地文件路径,可重复传
                                   例如: -local libsnappyjava.so=/opt/libs/libsnappyjava.so
  -mirror <url>                    本地库镜像服务器基础 URL,{lib} {os} {arch} 作为占位
                                   例如: -mirror https://mirrors.example.com/native/{lib}/{os}/{arch}/{libfile}
  -download                        实际下载缺失的本地库到 outdir (默认只打印 URL)
  -timeout <秒>                    下载超时时间 (默认: 60)
  -lang <zh|en>                    语言 (默认: 自动检测系统语言)

原理:
  Java 加载本地库时优先搜索 -Djava.library.path 指定的目录,找到同名文件后
  不会再从 jar 包内部提取。overlay 命令把所需的本地库放到外部目录,就能
  跳过 jar 内部的同名库(方便补架构、换版本、修复漏洞等)。

示例:
  # 仅分析,打印建议和下载 URL
  JavaArchitectureAnalysisTool overlay ruoyi-admin.jar

  # 指定目标平台/架构
  JavaArchitectureAnalysisTool overlay app.jar -os linux -arch aarch64

  # 指定本地已有的库 + 自动下载缺失的
  JavaArchitectureAnalysisTool overlay app.jar \
    -local libsnappyjava.so=/opt/libs/libsnappyjava.so \
    -mirror https://mirrors.example.com/native/{lib}/{os}/{arch}/{libfile} \
    -download -outdir /opt/app-native-libs

  # 启动 jar 时加上 java.library.path
  java -Djava.library.path=/opt/app-native-libs -jar app.jar

--- English ---

Usage:
  JavaArchitectureAnalysisTool pom <pom.xml path>           Parse Maven pom.xml
  JavaArchitectureAnalysisTool jar <jar file or dir path>   Parse .jar files (identify C/C++ native architectures)
                                                           Recursively scans all .jar files when given a directory, merges results
  JavaArchitectureAnalysisTool overlay <jar file path>      Generate native library overlay plan (java.library.path)
                                                           Prioritizes external .so/.dylib/.dll, skips in-jar libraries with same name
  JavaArchitectureAnalysisTool help                         Show this help message

Overlay options:
  -os <linux|darwin|windows|...>   Target OS (default: current system)
  -arch <x86_64|aarch64|arm64|...> Target CPU architecture (default: current arch)
  -outdir <path>                   Output directory for external libraries (default: ./native-overlay)
  -local <libname=path>            Specify local file path for a native library, can be repeated
                                   e.g.: -local libsnappyjava.so=/opt/libs/libsnappyjava.so
  -mirror <url>                    Mirror server URL template, {lib} {os} {arch} as placeholders
                                   e.g.: -mirror https://mirrors.example.com/native/{lib}/{os}/{arch}/{libfile}
  -download                        Actually download missing native libraries to outdir (default: print URLs only)
  -timeout <seconds>               Download timeout (default: 60)
  -lang <zh|en>                    Language (default: auto-detect from system)

Principle:
  Java searches -Djava.library.path first when loading native libraries. Once a file with the same name is found,
  it won't extract from inside the jar. The overlay command places required native libraries in an external directory,
  allowing to skip same-named libraries inside the jar (useful for adding architectures, changing versions, fixing vulnerabilities, etc.).

Examples:
  # Analysis only, print suggestions and download URLs
  JavaArchitectureAnalysisTool overlay ruoyi-admin.jar

  # Specify target platform/architecture
  JavaArchitectureAnalysisTool overlay app.jar -os linux -arch aarch64

  # Specify existing local libraries + auto-download missing ones
  JavaArchitectureAnalysisTool overlay app.jar \
    -local libsnappyjava.so=/opt/libs/libsnappyjava.so \
    -mirror https://mirrors.example.com/native/{lib}/{os}/{arch}/{libfile} \
    -download -outdir /opt/app-native-libs

  # Add java.library.path when starting the jar
  java -Djava.library.path=/opt/app-native-libs -jar app.jar`)
}

// =====================================================
//
//	pom.xml 解析 / pom.xml parsing
//
// =====================================================
// reorderArgs 将混排的 flags 和位置参数重排为 flags 在前、位置参数在后 / reorderArgs reorders mixed flags and positional args so flags come first and positional args last
// Go 标准 flag 只识别位置参数之前的 flags,这里手动重排 / Go's standard flag only recognizes flags before positional args; we manually reorder here
func reorderArgs(args []string, boolFlags map[string]bool) []string {
	reordered := make([]string, 0, len(args))
	var posArgs []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			reordered = append(reordered, a)
			if !strings.Contains(a, "=") {
				name := strings.TrimPrefix(a, "-")
				name = strings.TrimPrefix(name, "-")
				if !boolFlags["-"+name] {
					if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
						reordered = append(reordered, args[i+1])
						i++
					}
				}
			}
		} else {
			posArgs = append(posArgs, a)
		}
	}
	for _, a := range posArgs {
		reordered = append(reordered, a)
	}
	return reordered
}

func runPom(args []string) {
	args = reorderArgs(args, map[string]bool{"-offline": true, "-h": true, "-help": true})
	fs := flag.NewFlagSet("pom", flag.ExitOnError)
	offline := fs.Bool("offline", true, "是否只使用本地 ~/.m2/repository,不访问远程 Maven Central")
	remote := fs.String("remote", "", "远程仓库 URL (仅当 -offline=false 时生效,默认 Maven Central)")
	langFlag := fs.String("lang", detectLang(), "Language: zh/en (auto-detect from system)")
	_ = fs.Parse(args)
	SetLang(*langFlag)

	if fs.NArg() < 1 {
		stdlog.Fatal(T("pom_missing"))
	}
	pomFile := fs.Arg(0)

	f, err := os.Open(pomFile)
	if err != nil {
		stdlog.Fatalf(T("open_failed"), pomFile, err)
	}
	defer f.Close()

	var (
		libs []types.Library
		deps []types.Dependency
	)
	if *remote != "" {
		libs, deps, err = pom.NewParser(pomFile,
			pom.WithOffline(*offline),
			pom.WithRemoteRepos([]string{*remote}),
		).Parse(f)
	} else {
		libs, deps, err = pom.NewParser(pomFile,
			pom.WithOffline(*offline),
		).Parse(f)
	}
	if err != nil {
		stdlog.Fatalf(T("parse_failed"), "pom.xml", err)
	}

	printResult(fmt.Sprintf("pom.xml: %s", pomFile), libs, deps, nil)
}

// =====================================================
//
//	.jar 解析 (含架构扫描) / .jar parsing (including architecture scanning)
//
// =====================================================
func runJar(args []string) {
	args = reorderArgs(args, map[string]bool{"-offline": true, "-h": true, "-help": true})
	fs := flag.NewFlagSet("jar", flag.ExitOnError)
	offline := fs.Bool("offline", false, "是否离线模式 (true 时跳过 Maven Central 查询,仅靠 jar 内嵌元数据识别)")
	langFlag := fs.String("lang", detectLang(), "Language: zh/en (auto-detect from system)")
	_ = fs.Parse(args)
	SetLang(*langFlag)

	if fs.NArg() < 1 {
		stdlog.Fatal(T("jar_missing"))
	}
	target := fs.Arg(0)

	fi, err := os.Stat(target)
	if err != nil {
		stdlog.Fatalf(T("stat_failed"), target, err)
	}

	if fi.IsDir() {
		// 目录模式:遍历所有 .jar 文件,合并结果 / Directory mode: traverse all .jar files, merge results
		runJarDir(target, *offline)
		return
	}

	// 单文件模式 / Single file mode
	runJarFile(target, *offline)
}

// runJarFile 扫描单个 jar 文件 / runJarFile scans a single jar file
func runJarFile(jarPath string, offline bool) {
	fi, err := os.Stat(jarPath)
	if err != nil {
		stdlog.Fatalf(T("stat_failed"), jarPath, err)
	}

	f, err := os.Open(jarPath)
	if err != nil {
		stdlog.Fatalf(T("open_failed"), jarPath, err)
	}
	defer f.Close()

	// (1) go-dep-parser 的常规 Java 库解析 / (1) Standard Java library parsing via go-dep-parser
	var client jar.Client
	if !offline {
		client = sonatype.New()
	}
	p := jar.NewParser(client, jar.WithFilePath(jarPath), jar.WithSize(fi.Size()), jar.WithOffline(offline))
	libs, deps, err := p.Parse(f)
	if err != nil {
		stdlog.Fatalf(T("parse_failed"), jarPath, err)
	}

	// (2) 额外扫描 jar 内是否包含 C/C++ 本地二进制产物并识别架构 / (2) Additionally scan the jar for C/C++ native binary artifacts and identify architectures
	nativeScan := scanJarNativeArtifacts(jarPath)

	printResult(fmt.Sprintf("jar: %s", maskPath(jarPath)), libs, deps, &nativeScan)
}

// runJarDir 遍历目录下所有 .jar 文件 (含子目录),逐个扫描并合并结果 / runJarDir traverses all .jar files under a directory (including subdirectories), scans each and merges results
// 适用场景: / Applicable scenarios:
//   - Hadoop/Spark tar 解压后的 share/hadoop/common/lib/ 目录 /   - share/hadoop/common/lib/ directory after extracting Hadoop/Spark tar
//   - Maven 本地仓库 ~/.m2/repository/ 目录 /   - Maven local repository ~/.m2/repository/ directory
//   - 任意含多个独立 jar 的目录 /   - Any directory containing multiple independent jars
func runJarDir(dirPath string, offline bool) {
	// 收集目录下所有 .jar 文件 / Collect all .jar files under the directory
	var jarFiles []string
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // 忽略访问错误,继续遍历 / Ignore access errors, continue traversal
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(path), ".jar") {
			jarFiles = append(jarFiles, path)
		}
		return nil
	})
	if err != nil {
		stdlog.Fatalf(T("walk_failed"), dirPath, err)
	}
	if len(jarFiles) == 0 {
		stdlog.Fatalf(T("no_jar_found"), dirPath)
	}

	fmt.Fprint(os.Stderr, T("scan_dir", maskPath(dirPath), len(jarFiles))+"\n\n")

	// 合并所有 jar 的结果 / Merge results from all jars
	var (
		allLibs  []types.Library
		allDeps  []types.Dependency
		mergedNS = &ScanResult{}
	)
	jarWithNativeCount := 0
	jarParsedCount := 0

	for _, jf := range jarFiles {
		// 逐个打开 jar,跑 go-dep-parser + 本地架构扫描 / Open each jar, run go-dep-parser + native architecture scan
		fi, err := os.Stat(jf)
		if err != nil {
			continue
		}

		f, err := os.Open(jf)
		if err != nil {
			continue
		}

		var client jar.Client
		if !offline {
			client = sonatype.New()
		}
		p := jar.NewParser(client, jar.WithFilePath(jf), jar.WithSize(fi.Size()), jar.WithOffline(offline))
		libs, deps, err := p.Parse(f)
		f.Close()
		if err != nil {
			// 解析失败的 jar 跳过,但仍然扫本地架构 / Skip jars that fail to parse, but still scan native architectures
			continue
		}
		jarParsedCount++
		allLibs = append(allLibs, libs...)
		allDeps = append(allDeps, deps...)

		// 扫本地架构 / Scan native architectures
		ns := scanJarNativeArtifacts(jf)
		if ns.HasNative {
			jarWithNativeCount++
			// 把每个 artifact 的路径前缀改成相对目录的路径,方便看来源 / Change each artifact's path prefix to a path relative to the directory, for easier source identification
			rel, err := filepath.Rel(dirPath, jf)
			if err != nil {
				rel = jf
			}
			for _, art := range ns.Artifacts {
				// 把原本的 "xxx.jar!path" 改成 "relpath!path" / Change the original "xxx.jar!path" to "relpath!path"
				// 原 Path 第一段是 filepath.Base(jf),这里替换成相对路径 / The first segment of the original Path is filepath.Base(jf), replaced here with a relative path
				parts := strings.SplitN(art.Path, "!", 2)
				if len(parts) == 2 {
					art.Path = rel + "!" + parts[1]
				}
				mergedNS.Artifacts = append(mergedNS.Artifacts, art)
			}
		}
	}

	// 聚合合并后的 ScanResult / Aggregate the merged ScanResult
	mergedNS.NativeCount = len(mergedNS.Artifacts)
	mergedNS.HasNative = mergedNS.NativeCount > 0
	platSet := map[string]struct{}{}
	archSet := map[string]struct{}{}
	for _, a := range mergedNS.Artifacts {
		if a.Platform != "" && a.Platform != "未知" {
			platSet[a.Platform] = struct{}{}
		}
		for _, arch := range a.Archs {
			if arch != "" {
				archSet[arch] = struct{}{}
			}
		}
	}
	mergedNS.Platforms = sortedKeys(platSet)
	mergedNS.Archs = sortedKeys(archSet)

	fmt.Fprint(os.Stderr, T("scan_complete", jarParsedCount, len(jarFiles), jarWithNativeCount)+"\n\n")

	title := T("dir_scan_title", maskPath(dirPath), len(jarFiles))
	printResult(title, allLibs, allDeps, mergedNS)
}

// =====================================================
//
//	overlay 子命令 - 本地库覆盖方案 / overlay subcommand - native library overlay plan
//
// =====================================================

// OverlayAction 表示单个本地库的处理方案 / OverlayAction represents the handling plan for a single native library
type OverlayAction struct {
	LibraryName    string     // 归一化后的库文件名,如 libsnappyjava.so / Normalized library filename, e.g. libsnappyjava.so
	LibRoot        string     // 库的根名(去掉版本和后缀),如 libsnappyjava / Library root name (without version and suffix), e.g. libsnappyjava
	Platform       string     // Linux / macOS / Windows
	Format         string     // ELF / Mach-O / PE
	TargetArch     string     // 目标架构,如 x86_64 / Target architecture, e.g. x86_64
	SupportedArchs []string   // 该库在目标平台已支持的架构集合 / Set of architectures already supported by this library on the target platform
	Status         string     // "本地指定" / "已有" / "需下载" / "缺少来源" / "不匹配" / "locally specified" / "exists" / "needs download" / "missing source" / "mismatch"
	SourceLocal    string     // -local 指定的本地文件路径 / Local file path specified by -local
	SourceJarPath  string     // jar 内部路径 (用于展示) / Internal path inside the jar (for display)
	DownloadURLs   []string   // 候选下载 URL 列表 (支持多源回退) / List of candidate download URLs (supports multi-source fallback)
	OutPath        string     // 写入 outdir 后的目标路径 / Target path after writing to outdir
	SizeJar        int64      // jar 内同名文件大小 (用于对比) / Size of the same-named file inside the jar (for comparison)
	SizeLocal      int64      // 本地文件大小 (如有) / Local file size (if any)
	SourceCoord    MavenCoord // 来源 jar 的 Maven 坐标 / Source jar Maven coordinates
	SourceJarName  string     // 来源 jar 文件名 (内层 jar) / Source jar filename (inner jar)
	OrigLibNames   []string   // jar 内原始文件名列表 (用于创建兼容软链接) / Original filenames inside jar (for compat symlinks)
	LocalArchInfo  string     // 本地/已有文件的架构扫描结果 / Architecture scan result of the local/existing file
}

// mapFlag 自定义 flag,支持重复传 -local key=value / mapFlag custom flag, supports repeated -local key=value
type mapFlag map[string]string

func (m *mapFlag) String() string { return fmt.Sprintf("%v", map[string]string(*m)) }
func (m *mapFlag) Set(v string) error {
	idx := strings.Index(v, "=")
	if idx <= 0 {
		return fmt.Errorf("格式应为 libname=path, 实际: %s", v)
	}
	if *m == nil {
		*m = mapFlag{}
	}
	(*m)[strings.TrimSpace(v[:idx])] = strings.TrimSpace(v[idx+1:])
	return nil
}

// currentOS 返回适合镜像 URL 的 OS 名 / currentOS returns the OS name suitable for mirror URLs
func currentOS() string {
	switch runtimeOS() {
	case "darwin":
		return "darwin"
	case "windows":
		return "windows"
	default:
		return "linux"
	}
}

// currentArch 返回适合镜像 URL 的架构名 / currentArch returns the architecture name suitable for mirror URLs
func currentArch() string {
	switch runtimeArch() {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	default:
		return runtimeArch()
	}
}

// jarFormatToOS jar 内文件格式 → URL 中使用的 OS 名 / jarFormatToOS jar internal file format → OS name used in URL
func jarFormatToOS(format string) string {
	switch format {
	case "ELF":
		return "linux"
	case "Mach-O":
		return "darwin"
	case "PE":
		return "windows"
	case "XCOFF":
		return "aix"
	default:
		return ""
	}
}

// normalizeArch 归一化 CPU 架构名,统一别名 / normalizeArch normalizes CPU architecture names and unifies aliases
// amd64 → x86_64, arm64 → aarch64, 去掉括号说明等 / amd64 → x86_64, arm64 → aarch64, remove parenthetical notes etc.
func normalizeArch(a string) string {
	aa := strings.ToLower(a)
	// 去掉括号及后面的说明,如 "x86_64 (AMD64)" → "x86_64" / Remove parentheses and following notes, e.g. "x86_64 (AMD64)" → "x86_64"
	if i := strings.Index(aa, " "); i > 0 {
		aa = aa[:i]
	}
	if i := strings.Index(aa, "("); i > 0 {
		aa = aa[:i]
	}
	aa = strings.TrimSpace(aa)
	switch aa {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	case "i686":
		return "i386"
	case "x86":
		return "i386"
	case "arm32", "armv7l", "armv6l":
		return "arm"
	default:
		return aa
	}
}

// normalizePlatform 归一化平台名,统一别名 / normalizePlatform normalizes platform names and unifies aliases
// macOS/osx → darwin, win → windows / macOS/osx → darwin, win → windows
func normalizePlatform(p string) string {
	pp := strings.ToLower(p)
	switch pp {
	case "macos", "osx":
		return "darwin"
	case "win":
		return "windows"
	default:
		return pp
	}
}

// normalizeLibKey 在 normalizeLibraryName 基础上进一步归一化,用于 overlay 分组 key / normalizeLibKey further normalizes on top of normalizeLibraryName, used as overlay grouping key
// 额外做:去掉 lib 前缀、去掉版本号,让 libsnappyjava.so 和 snappyjava.so 合并 / Additionally: remove lib prefix, remove version numbers, so libsnappyjava.so and snappyjava.so are merged
func normalizeLibKey(fileName string) string {
	name := normalizeLibraryName(fileName)
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	// 去掉 lib 前缀 / Remove lib prefix
	base = strings.TrimPrefix(base, "lib")
	// 去掉版本号:匹配 -1.5.5-5 或 _1.5.5 这种模式 / Remove version numbers: match patterns like -1.5.5-5 or _1.5.5
	// 找到第一个数字开头的位置,如果前面是分隔符,就截断 / Find the first position starting with a digit; if preceded by a separator, truncate there
	for i, r := range base {
		if r >= '0' && r <= '9' {
			if i > 0 && (base[i-1] == '-' || base[i-1] == '_') {
				base = base[:i-1]
				break
			}
		}
	}
	base = strings.Trim(base, "-_. ")
	return base + ext
}

// libRootFromName 从文件名中提取库根名 (去版本、去架构、去 lib 前缀) / libRootFromName extracts the library root name from the filename (without version, architecture, or lib prefix)
// 基于 normalizeLibKey 进一步去掉扩展名,用于镜像 URL 的 {lib} 占位符 / Based on normalizeLibKey, further removes the extension, used for the {lib} placeholder in mirror URLs
// libzstd-jni-1.5.5-5.so → zstdjni, libsnappyjava.so → snappyjava / libzstd-jni-1.5.5-5.so → zstdjni, libsnappyjava.so → snappyjava
func libRootFromName(fileName string) string {
	name := normalizeLibKey(fileName)
	return strings.TrimSuffix(name, filepath.Ext(name))
}

// expandMirrorURL 替换 mirror 模板中的占位符 / expandMirrorURL replaces placeholders in the mirror template
func expandMirrorURL(tpl, libName, libRoot, osName, arch string) string {
	r := strings.NewReplacer(
		"{lib}", libRoot,
		"{libfile}", libName,
		"{os}", osName,
		"{arch}", arch,
	)
	return r.Replace(tpl)
}

// mavenMirrorBases Maven Central 镜像源基础 URL 列表 (按优先级排序,国内优先) / mavenMirrorBases Maven Central mirror base URL list (sorted by priority, domestic first)
// 用于构造 jar 包下载 URL: {base}/{groupIdPath}/{artifactId}/{version}/{jarFile} / Used to build jar download URLs: {base}/{groupIdPath}/{artifactId}/{version}/{jarFile}
var mavenMirrorBases = []struct {
	Name string
	Base string
}{
	{"阿里云", "https://maven.aliyun.com/repository/central"},
	{"华为云", "https://repo.huaweicloud.com/repository/maven-central"},
	{"腾讯云", "https://mirrors.cloud.tencent.com/nexus/repository/maven-public"},
	{"Maven Central", "https://repo1.maven.org/maven2"},
	{"Maven Central (备用)", "https://repo.maven.apache.org/maven2"},
}

// extractClassifier 从 jar 文件名中提取 classifier / extractClassifier extracts the classifier from a jar filename
// jar 文件名格式: {artifactId}-{version}-{classifier}.jar / Jar filename format: {artifactId}-{version}-{classifier}.jar
// 例如: netty-transport-native-epoll-4.1.128.Final-linux-x86_64.jar → linux-x86_64 / e.g.: netty-transport-native-epoll-4.1.128.Final-linux-x86_64.jar → linux-x86_64
func extractClassifier(jarName, artifactID, version string) string {
	base := strings.TrimSuffix(jarName, ".jar")
	prefix := artifactID + "-" + version + "-"
	if strings.HasPrefix(base, prefix) {
		return strings.TrimPrefix(base, prefix)
	}
	// 没有 classifier / No classifier
	return ""
}

// replaceClassifierArch 把 classifier 中的架构关键词替换为目标架构 / replaceClassifierArch replaces architecture keywords in the classifier with the target architecture
// 不同库的架构命名约定不同,生成多个候选: / Different libraries use different architecture naming conventions, generate multiple candidates:
//
//	x86_64 → aarch_64 (netty 约定) / aarch64 (通用) / arm64 (Apple 约定) / x86_64 → aarch_64 (netty convention) / aarch64 (generic) / arm64 (Apple convention)
func replaceClassifierArch(classifier, targetArch string) []string {
	if classifier == "" {
		return nil
	}
	// 原架构关键词 → 目标架构候选列表 (按各库常见命名约定排列) / Original architecture keyword → target architecture candidate list (ordered by common naming conventions of various libraries)
	// 注意:必须按长度降序匹配,否则 "x86" 会先于 "x86_64" 匹配,导致 "linux-x86_64" → "linux-aarch_64_64" / Note: must match in descending length order, otherwise "x86" would match before "x86_64", causing "linux-x86_64" → "linux-aarch_64_64"
	archPairs := []struct {
		Old string
		New []string
	}{
		{"aarch_64", []string{"x86_64", "amd64"}},
		{"aarch64", []string{"x86_64", "amd64"}},
		{"arm64", []string{"x86_64", "amd64"}},
		{"x86_64", []string{"aarch_64", "aarch64", "arm64"}},
		{"amd64", []string{"aarch_64", "aarch64", "arm64"}},
		{"i386", []string{"aarch_64", "aarch64", "arm64"}},
		{"i686", []string{"aarch_64", "aarch64", "arm64"}},
		{"x86", []string{"aarch_64", "aarch64", "arm64"}},
	}
	lower := strings.ToLower(classifier)
	for _, pair := range archPairs {
		if strings.Contains(lower, pair.Old) {
			var results []string
			for _, newArch := range pair.New {
				results = append(results, strings.Replace(lower, pair.Old, newArch, 1))
			}
			return results
		}
	}
	return nil
}

// buildMavenJarURLs 根据 Maven 坐标和原 jar 名生成候选 jar 下载 URL 列表 / buildMavenJarURLs generates a list of candidate jar download URLs based on Maven coordinates and the original jar name
// 策略: / Strategy:
//  1. 从原 jar 名提取 classifier,替换架构关键词生成目标 classifier 候选 /  1. Extract classifier from the original jar name, replace architecture keywords to generate target classifier candidates
//  2. 对每个 classifier 候选,用各 Maven 镜像源构造 URL /  2. For each classifier candidate, construct URLs using each Maven mirror source
//  3. 如果没有 classifier (所有架构在一个 jar 里),直接下载不带 classifier 的 jar /  3. If there is no classifier (all architectures are in one jar), download the jar without classifier directly
func buildMavenJarURLs(coord MavenCoord, sourceJarName, targetArch string) []string {
	if coord.GroupID == "" || coord.ArtifactID == "" || coord.Version == "" {
		return nil
	}
	groupPath := strings.ReplaceAll(coord.GroupID, ".", "/")

	// 取文件名 (sourceJarName 可能含路径前缀,如 BOOT-INF/lib/xxx.jar) / Take the filename (sourceJarName may contain a path prefix, e.g. BOOT-INF/lib/xxx.jar)
	jarBase := filepath.Base(sourceJarName)

	// 生成候选 jar 文件名列表 / Generate the list of candidate jar filenames
	var jarFiles []string
	classifier := extractClassifier(jarBase, coord.ArtifactID, coord.Version)
	if classifier == "" {
		// 没有 classifier,直接用 artifactId-version.jar / No classifier, use artifactId-version.jar directly
		jarFiles = append(jarFiles, fmt.Sprintf("%s-%s.jar", coord.ArtifactID, coord.Version))
	} else {
		// 有 classifier,替换架构关键词 / Has classifier, replace architecture keywords
		targetClassifiers := replaceClassifierArch(classifier, targetArch)
		for _, tc := range targetClassifiers {
			jarFiles = append(jarFiles, fmt.Sprintf("%s-%s-%s.jar", coord.ArtifactID, coord.Version, tc))
		}
		// 也保留原 classifier 的 jar (可能同一个 jar 包含多架构) / Also keep the jar with the original classifier (the same jar may contain multiple architectures)
		jarFiles = append(jarFiles, fmt.Sprintf("%s-%s-%s.jar", coord.ArtifactID, coord.Version, classifier))
	}

	// 对每个候选 jar 文件名,生成各镜像源的 URL / For each candidate jar filename, generate URLs for each mirror source
	var urls []string
	for _, jf := range jarFiles {
		for _, mirror := range mavenMirrorBases {
			url := fmt.Sprintf("%s/%s/%s/%s/%s", mirror.Base, groupPath, coord.ArtifactID, coord.Version, jf)
			urls = append(urls, url)
		}
	}
	return urls
}

func runOverlay(args []string) {
	args = reorderArgs(args, map[string]bool{"-download": true, "-h": true, "-help": true})

	fs := flag.NewFlagSet("overlay", flag.ExitOnError)
	targetOS := fs.String("os", currentOS(), "目标操作系统 (linux/darwin/windows/aix 等)")
	targetArch := fs.String("arch", currentArch(), "目标 CPU 架构 (x86_64/aarch64/arm64/arm/riscv64 等)")
	outdir := fs.String("outdir", "native-overlay", "外部库输出目录")
	var locals mapFlag
	fs.Var(&locals, "local", "指定本地库文件,格式: libname=path,可重复")
	mirror := fs.String("mirror", "", "镜像服务器 URL 模板,占位符: {lib} {libfile} {os} {arch}")
	doDownload := fs.Bool("download", false, "实际下载缺失的库(默认只打印 URL)")
	timeout := fs.Int("timeout", 60, "下载超时秒数")
	langFlag := fs.String("lang", detectLang(), "Language: zh/en (auto-detect from system)")
	_ = fs.Parse(args)
	SetLang(*langFlag)

	if fs.NArg() < 1 {
		stdlog.Fatal(T("overlay_missing"))
	}
	jarPath := fs.Arg(0)

	// 扫描 jar 内的本地产物 / Scan native artifacts inside the jar
	ns := scanJarNativeArtifacts(jarPath)
	if !ns.HasNative {
		fmt.Printf("%s\n\n", T("overlay_header", maskPath(jarPath)))
		fmt.Println(T("no_native"))
		return
	}

	// 归一化目标 OS/Arch 以便匹配 / Normalize target OS/Arch for matching
	wantOS := strings.ToLower(*targetOS)
	wantArch := strings.ToLower(*targetArch)
	// 归一化 darwin/macos / x86_64/amd64 / aarch64/arm64 同义 / Normalize darwin/macos / x86_64/amd64 / aarch64/arm64 synonyms
	switch wantOS {
	case "macos", "osx":
		wantOS = "darwin"
	case "win":
		wantOS = "windows"
	}
	switch wantArch {
	case "amd64":
		wantArch = "x86_64"
	case "arm64":
		wantArch = "aarch64"
	}

	// 确保输出目录存在 / Ensure the output directory exists
	if err := os.MkdirAll(*outdir, 0o755); err != nil {
		stdlog.Fatalf(T("create_outdir_fail"), *outdir, err)
	}
	outAbs, _ := filepath.Abs(*outdir)

	fmt.Printf("%s\n", T("overlay_header", maskPath(jarPath)))
	fmt.Printf("  %s\n", T("target_platform", wantOS, wantArch))
	fmt.Printf("  %s\n\n", T("output_dir", maskPath(outAbs)))

	// 初始化 jar 缓存目录 / Initialize jar cache directory
	if err := ensureCacheDir(); err != nil {
		fmt.Fprintf(os.Stderr, "  %s\n", T("cannot_read"))
	}

	// 检测跨平台部署,提前通知链接策略 / Detect cross-platform deployment, notify link strategy in advance
	if runtime.GOOS != wantOS {
		fmt.Printf("  %s\n\n", T("cross_platform_notice", wantOS, runtime.GOOS))
	}

	// 按(归一化库 key)聚合 artifacts,统计每个库在每个平台支持的架构集合 / Aggregate artifacts by (normalized library key), count the set of architectures supported by each library on each platform
	// 用 normalizeLibKey 做分组:去掉 lib 前缀、版本号、架构/平台关键词 / Use normalizeLibKey for grouping: remove lib prefix, version numbers, architecture/platform keywords
	// 这样 libsnappyjava.so 和 snappyjava.so、libzstd-jni-1.5.5-5.so 都能正确合并 / So libsnappyjava.so, snappyjava.so, and libzstd-jni-1.5.5-5.so can all be merged correctly
	type libInfo struct {
		platformArchs map[string]map[string]bool // platform → set(arch)
		platformFmt   map[string]string          // platform → format (取一个样本) / platform → format (take one sample)
		platformPath  map[string]string          // platform → 一个 jar 内路径样本 / platform → a sample path inside the jar
		platformSize  map[string]int64           // platform → 样本文件大小 / platform → sample file size
		jarLibName    map[string]string          // platform → jar 内原文件名 / platform → original filename inside the jar
		jarLibNames   map[string][]string        // platform → jar 内所有原文件名 (用于兼容软链接) / platform → all original filenames (for compat symlinks)
		displayName   string                     // 归一化展示名 (保留 lib 前缀,用于输出) / Normalized display name (keep lib prefix, for output)
		sourceCoord   MavenCoord                 // 来源 jar 的 Maven 坐标 / Source jar Maven coordinates
		sourceJarName string                     // 来源 jar 文件名 / Source jar filename
	}
	libInfos := map[string]*libInfo{}

	for _, art := range ns.Artifacts {
		if art.Platform == "" || art.Platform == "未知" || art.Format == "Unknown" || len(art.Archs) == 0 {
			continue
		}
		artOS := normalizePlatform(art.Platform)
		libFile := filepath.Base(art.Path)
		libKey := normalizeLibKey(libFile)
		displayName := normalizeLibraryName(libFile)
		info, ok := libInfos[libKey]
		if !ok {
			info = &libInfo{
				platformArchs: map[string]map[string]bool{},
				platformFmt:   map[string]string{},
				platformPath:  map[string]string{},
				platformSize:  map[string]int64{},
				jarLibName:    map[string]string{},
				jarLibNames:   map[string][]string{},
				displayName:   displayName,
				sourceCoord:   art.SourceCoord,
				sourceJarName: art.SourceJarName,
			}
			libInfos[libKey] = info
		}
		if info.platformArchs[artOS] == nil {
			info.platformArchs[artOS] = map[string]bool{}
		}
		for _, a := range art.Archs {
			info.platformArchs[artOS][normalizeArch(a)] = true
		}
		// 保留一个样本 (优先保留目标平台的) / Keep one sample (prefer the target platform)
		if _, exists := info.platformFmt[artOS]; !exists || artOS == wantOS {
			info.platformFmt[artOS] = art.Format
			info.platformPath[artOS] = art.Path
			info.platformSize[artOS] = art.FileSize
			info.jarLibName[artOS] = libFile
		}
		// 收集该平台所有原始文件名 (去重,用于创建兼容软链接) / Collect all original filenames for this platform (deduplicated, for compat symlinks)
		found := false
		for _, n := range info.jarLibNames[artOS] {
			if n == libFile {
				found = true
				break
			}
		}
		if !found {
			info.jarLibNames[artOS] = append(info.jarLibNames[artOS], libFile)
		}
	}

	// 筛选:在目标平台上,不支持目标架构的库 → 才需要 overlay / Filter: libraries that don't support the target architecture on the target platform → need overlay
	var actions []OverlayAction
	var supportedActions []OverlayAction // 已支持目标架构的库,用于展示 / Libraries that already support the target architecture, for display
	totalLibs := 0                       // jar 内本地库总数(归一化后) / Total native libraries inside the jar (after normalization)
	supportedCount := 0                  // 目标平台已支持目标架构的库数 / Number of libraries on the target platform that already support the target architecture
	missingCount := 0                    // 目标平台缺目标架构的库数 / Number of libraries on the target platform missing the target architecture
	otherPlatformCount := 0              // 仅存在于其他平台的库数 (如 .dll/.dylib) / Number of libraries only on other platforms (e.g. .dll/.dylib)

	for _, info := range libInfos {
		totalLibs++
		archs, hasPlatform := info.platformArchs[wantOS]

		// 该库在目标平台不存在 (如 linux 不会有 .dll),无需 overlay / This library doesn't exist on the target platform (e.g. Linux won't have .dll), no overlay needed
		if !hasPlatform {
			otherPlatformCount++
			continue
		}

		// 检查目标架构是否已支持 / Check whether the target architecture is already supported
		if archs[wantArch] {
			supportedCount++
			// 收集已支持的库,用于展示对比 / Collect supported libraries for display comparison
			samplePath := info.platformPath[wantOS]
			sampleSize := info.platformSize[wantOS]
			sampleFmt := info.platformFmt[wantOS]
			supportedArchList := []string{}
			for a := range archs {
				supportedArchList = append(supportedArchList, a)
			}
			sort.Strings(supportedArchList)
			normName := info.displayName
			suppAct := OverlayAction{
				LibraryName:    normName,
				Platform:       wantOS,
				Format:         sampleFmt,
				TargetArch:     wantArch,
				SupportedArchs: supportedArchList,
				SourceJarPath:  samplePath,
				SizeJar:        sampleSize,
				OutPath:        filepath.Join(outAbs, normName),
				SourceCoord:    info.sourceCoord,
				SourceJarName:  info.sourceJarName,
				Status:         "已支持",
			}
			supportedActions = append(supportedActions, suppAct)
			continue
		}

		// 这个库需要 overlay:目标平台有该库但缺目标架构 / This library needs overlay: the target platform has it but is missing the target architecture
		missingCount++
		libRoot := libRootFromName(info.displayName)
		samplePath := info.platformPath[wantOS]
		sampleSize := info.platformSize[wantOS]
		sampleFmt := info.platformFmt[wantOS]
		sampleLibName := info.jarLibName[wantOS]

		// 收集该库在目标平台支持的架构 / Collect architectures supported by this library on the target platform
		supportedArchs := []string{}
		for a := range archs {
			supportedArchs = append(supportedArchs, a)
		}
		sort.Strings(supportedArchs)
		normName := info.displayName
		act := OverlayAction{
			LibraryName:    info.displayName,
			LibRoot:        libRoot,
			Platform:       wantOS,
			Format:         sampleFmt,
			TargetArch:     wantArch,
			SupportedArchs: supportedArchs,
			SourceJarPath:  samplePath,
			SizeJar:        sampleSize,
			OutPath:        filepath.Join(outAbs, normName),
			SourceCoord:    info.sourceCoord,
			SourceJarName:  info.sourceJarName,
			OrigLibNames:   info.jarLibNames[wantOS],
		}

		// 1) 优先匹配 -local 指定的本地文件 / 1) Preferentially match local files specified by -local
		localPath := ""
		if sampleLibName != "" {
			if p, ok := locals[sampleLibName]; ok {
				localPath = p
			}
		}
		if localPath == "" {
			if p, ok := locals[normName]; ok {
				localPath = p
			}
		}

		// 标记状态 / Mark status
		if localPath != "" {
			if fi, err := os.Stat(localPath); err == nil {
				act.SourceLocal = localPath
				act.Status = "本地指定"
				act.SizeLocal = fi.Size()
				act.LocalArchInfo = scanDownloadedFile(localPath, fi.Size())
				actions = append(actions, act)
				continue
			}
		}

		// 2) 检查 outdir 里是否已经有同名文件了 / 2) Check whether a file with the same name already exists in outdir
		if fi, err := os.Stat(act.OutPath); err == nil {
			act.Status = "已有"
			act.SizeLocal = fi.Size()
			act.LocalArchInfo = scanDownloadedFile(act.OutPath, fi.Size())
			actions = append(actions, act)
			continue
		}

		// 3) 需要下载:生成候选 URL 列表 / 3) Needs download: generate candidate URL list
		osName := jarFormatToOS(sampleFmt)
		if osName == "" {
			osName = wantOS
		}
		if *mirror != "" {
			// 用户指定了镜像模板,生成 .so 文件直接下载 URL / User specified a mirror template, generate direct .so file download URL
			url := expandMirrorURL(*mirror, normName, libRoot, osName, wantArch)
			act.DownloadURLs = []string{url}
			act.Status = "需下载"
		} else if info.sourceCoord.GroupID != "" {
			// 有 Maven 坐标:从 Maven 仓库下载 jar 包,再从中提取 .so / Has Maven coordinates: download jar from Maven repository, then extract .so from it
			// 不同库的架构 classifier 命名不同 (如 netty 用 aarch_64,通用用 aarch64), / Different libraries use different architecture classifier naming (e.g. netty uses aarch_64, generic uses aarch64),
			// 生成多个候选 jar 文件名 × 多个镜像源 / Generate multiple candidate jar filenames × multiple mirror sources
			act.DownloadURLs = buildMavenJarURLs(info.sourceCoord, info.sourceJarName, wantArch)
			act.Status = "需下载"
		} else {
			// 没有 Maven 坐标,标记为缺少来源 / No Maven coordinates, mark as missing source
			act.Status = "缺少来源"
		}
		actions = append(actions, act)
	}

	// 排序输出 / Sort output
	sort.Slice(actions, func(i, j int) bool { return actions[i].LibraryName < actions[j].LibraryName })

	fmt.Println(T("overlay_plan"))
	fmt.Printf("  %s\n", T("total_libs", totalLibs))
	fmt.Printf("  %s\n", T("supported_arch", wantOS, wantArch, supportedCount))
	fmt.Printf("  %s\n", T("missing_arch", wantOS, wantArch, missingCount))
	if otherPlatformCount > 0 {
		fmt.Printf("  %s\n", T("other_platform", wantOS, otherPlatformCount))
	}
	if *mirror == "" {
		fmt.Printf("  %s\n", T("mirror_default", len(mavenMirrorBases)))
	} else {
		fmt.Printf("  %s\n", T("mirror_specified", *mirror))
	}
	fmt.Println()

	// 先展示已支持目标架构的库 (与 jar 命令架构分析口径一致) / First display libraries that already support the target architecture (consistent with the jar command's architecture analysis)
	if len(supportedActions) > 0 {
		fmt.Println("  " + T("already_supported"))
		sort.Slice(supportedActions, func(i, j int) bool { return supportedActions[i].LibraryName < supportedActions[j].LibraryName })
		for _, a := range supportedActions {
			suppTag := T("tag_supported")
			fmt.Printf("  %-50s ✓ %s [%s]\n", a.LibraryName, suppTag, strings.Join(a.SupportedArchs, "、"))
		}
		fmt.Println()
	}

	downloadList := []OverlayAction{}
	copyList := []OverlayAction{}
	for _, a := range actions {
		tag := ""
		switch a.Status {
		case "本地指定":
			tag = T("tag_local")
		case "已有":
			tag = T("tag_exist")
		case "需下载":
			tag = T("tag_download")
			downloadList = append(downloadList, a)
		case "缺少来源":
			tag = T("tag_missing")
		}
		// 检查和 jar 内部文件大小是否接近 (判断版本是否接近) / Check whether the size is close to the file inside the jar (to judge whether the versions are close)
		sizeHint := ""
		if a.SizeLocal > 0 && a.SizeJar > 0 {
			ratio := float64(a.SizeLocal) / float64(a.SizeJar)
			if ratio < 0.5 || ratio > 2.0 {
				sizeHint = T("size_hint", a.SizeLocal, a.SizeJar)
			}
		}

		// 带上该库在目标平台支持的架构标识 / Attach the architecture identifier supported by this library on the target platform
		archLabel := T("none")
		if len(a.SupportedArchs) > 0 {
			archLabel = "[" + strings.Join(a.SupportedArchs, "、") + "]"
		}

		fmt.Printf("  %-55s  %s\n", a.LibraryName, tag)
		fmt.Printf("    %s\n", T("target_arch", a.TargetArch, archLabel, a.TargetArch))
		fmt.Printf("    %s\n", T("output_path", maskPath(a.OutPath)))
		fmt.Printf("    %s\n", T("jar_sample", a.SourceJarPath, a.SizeJar))
		if a.SourceCoord.GroupID != "" {
			fmt.Printf("    %s\n", T("maven_info", a.SourceCoord.GroupID, a.SourceCoord.ArtifactID, a.SourceCoord.Version))
			if a.SourceJarName != "" {
				fmt.Printf("    %s\n", T("source_jar", a.SourceJarName))
			}
		}
		if a.SourceLocal != "" {
			fmt.Printf("    %s\n", T("local_source", maskPath(a.SourceLocal), a.SizeLocal, sizeHint))
		}
		if a.LocalArchInfo != "" {
			fmt.Printf("    %s\n", T("local_arch", a.LocalArchInfo))
		}
		if len(a.DownloadURLs) > 0 {
			if len(a.DownloadURLs) == 1 {
				fmt.Printf("    %s\n", T("download_url", a.DownloadURLs[0]))
			} else {
				fmt.Printf("    %s\n", T("candidate_sources", len(a.DownloadURLs)))
				for i, url := range a.DownloadURLs {
					fmt.Printf("      [%d] %s\n", i+1, url)
				}
			}
		}
		fmt.Println()
	}

	// 统计 / Statistics
	fmt.Printf("%s\n", T("statistics"))
	fmt.Printf("  %s\n", T("stat_total", totalLibs))
	fmt.Printf("  %s\n", T("stat_supported", wantOS, wantArch, supportedCount))
	fmt.Printf("  %s\n", T("stat_missing", wantOS, wantArch, missingCount))
	if otherPlatformCount > 0 {
		fmt.Printf("  %s\n", T("stat_other", wantOS, otherPlatformCount))
	}
	// 重新算下各状态数量 / Recount the quantity of each status
	countStat := map[string]int{}
	for _, a := range actions {
		countStat[a.Status]++
	}
	if len(countStat) > 0 {
		keys := make([]string, 0, len(countStat))
		for k := range countStat {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		stats := make([]string, 0, len(keys))
		for _, k := range keys {
			stats = append(stats, fmt.Sprintf("%s=%d", statusName(k), countStat[k]))
		}
		fmt.Printf("  %s\n", T("stat_dist", strings.Join(stats, ", ")))
	}

	// 执行下载和复制 / Perform download and copy
	client := &http.Client{Timeout: time.Duration(*timeout) * time.Second}
	processed := 0
	failed := 0

	if *doDownload {
		// 先复制本地指定 / First copy locally specified files
		for _, a := range actions {
			if a.Status == "本地指定" {
				if err := copyFile(a.SourceLocal, a.OutPath); err != nil {
					fmt.Fprintf(os.Stderr, "  %s\n", T("copy_fail", a.SourceLocal, err))
					failed++
				} else {
					processed++
					copyList = append(copyList, a)
					// 为原始文件名创建兼容链接 / Create compat links for original filenames
					createCompatLinks(a.OutPath, a.OrigLibNames, wantOS, wantArch)
				}
			}
		}
		// 再下载 (支持多源回退) / Then download (supports multi-source fallback)
		for _, a := range downloadList {
			fmt.Fprintf(os.Stderr, "  %s\n", T("downloading", a.LibraryName, maskPath(a.OutPath)))
			success := false
			var lastErr error
			useCache := a.SourceCoord.GroupID != "" && *mirror == ""
			// 步骤 1: Maven 模式下先查所有候选 URL 对应的缓存,命中则跳过下载 (直接从缓存 jar 提取) / Step 1: Maven mode — check cache for all candidate URLs first, skip download on cache hit (extract directly from cached jar)
			if useCache {
				for _, url := range a.DownloadURLs {
					jarFile := jarFileNameFromURL(url)
					cp := cachePathForJar(a.SourceCoord, jarFile)
					if fi, err := os.Stat(cp); err == nil && fi.Size() > 0 {
						fmt.Fprintf(os.Stderr, "%s\n", T("cache_hit", maskPath(cp)))
						if err := extractSOFromJar(cp, a.OutPath, a.TargetArch, a.LibraryName); err != nil {
							fmt.Fprintf(os.Stderr, "      %s\n", T("download_fail", err))
							lastErr = err
							os.Remove(a.OutPath)
							continue
						}
						success = true
						break
					}
				}
			}
			if !success {
				// 步骤 2: 缓存未命中,正常下载 / Step 2: cache miss, download normally
				for i, url := range a.DownloadURLs {
					fmt.Fprintf(os.Stderr, "    %s\n", T("try_source", i+1, url))
					if useCache {
						// Maven 模式: 下载到 .jarCache 目录,再从缓存提取 / Maven mode: download to .jarCache, then extract from cache
						jarFile := jarFileNameFromURL(url)
						cp := cachePathForJar(a.SourceCoord, jarFile)
						// 创建缓存子目录 (如不存在) / Create cache subdir if missing
						if err := os.MkdirAll(filepath.Dir(cp), 0755); err != nil {
							lastErr = err
							continue
						}
						fmt.Fprintf(os.Stderr, "      %s\n", T("cache_downloading", maskPath(cp)))
						if err := downloadFile(client, url, cp); err != nil {
							fmt.Fprintf(os.Stderr, "      %s\n", T("download_fail", err))
							lastErr = err
							continue
						}
						if fi, err := os.Stat(cp); err == nil {
							fmt.Fprintf(os.Stderr, "%s\n", T("cache_saved", maskPath(cp), fi.Size()))
						}
						// 从刚下载的缓存 jar 中提取 .so / Extract .so from the freshly downloaded cached jar
						if err := extractSOFromJar(cp, a.OutPath, a.TargetArch, a.LibraryName); err != nil {
							fmt.Fprintf(os.Stderr, "      %s\n", T("download_fail", err))
							lastErr = err
							os.Remove(a.OutPath)
							continue
						}
					} else {
						// 直接下载 .so 文件 (-mirror 模式) / Download .so file directly (-mirror mode)
						if err := downloadFile(client, url, a.OutPath); err != nil {
							fmt.Fprintf(os.Stderr, "      %s\n", T("download_fail", err))
							lastErr = err
							os.Remove(a.OutPath)
							continue
						}
					}
					success = true
					break
				}
			}
			if success {
				if fi, err := os.Stat(a.OutPath); err == nil {
					// 扫描下载文件的架构信息 / Scan the architecture info of the downloaded file
					archInfo := scanDownloadedFile(a.OutPath, fi.Size())
					fmt.Fprintf(os.Stderr, "      %s\n", T("download_success", fi.Size(), archInfo))
				}
				// 为原始文件名创建兼容链接 / Create compat links for original filenames
				createCompatLinks(a.OutPath, a.OrigLibNames, wantOS, wantArch)
			}
			if !success {
				fmt.Fprintf(os.Stderr, "    %s\n", T("all_sources_fail", lastErr))
				failed++
				os.Remove(a.OutPath)
			} else {
				processed++
			}
		}
	} else if len(downloadList) > 0 && len(copyList) == 0 {
		// 没执行下载,提示需要的 URL 数 / Did not perform download, prompt the number of URLs needed
		fmt.Printf("\n%s\n", T("need_download", len(downloadList), maskPath(outAbs)))
	}

	fmt.Println()
	fmt.Println("--- Java 启动参数建议 ---")
	jarAbs, _ := filepath.Abs(jarPath)
	fmt.Printf("  %s\n\n", T("java_cmd", maskPath(outAbs), maskPath(jarAbs)))
	fmt.Println("  " + T("java_cmd_hint"))

	if failed > 0 {
		fmt.Fprintf(os.Stderr, "\n%s\n", T("process_fail", failed))
		os.Exit(1)
	}
}

// copyFile 复制文件,保留权限 / copyFile copies a file, preserving permissions
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	out.Close()
	// 保留源文件权限 / Preserve source file permissions
	if si, err := os.Stat(src); err == nil {
		_ = os.Chmod(dst, si.Mode())
	}
	return nil
}

// createCompatLinks 为原始文件名创建兼容链接,使 JVM 的 loadLibrary("foo-arm64") 也能命中 / createCompatLinks creates compat links for original filenames, so JVM's loadLibrary("foo-arm64") also hits
// 跨平台策略: 当前 OS 与目标 OS 一致时 → 软链接优先 (同文件系统高效) / Cross-platform strategy: when current OS matches target OS → symlink first (efficient on same filesystem)
// 当前 OS 与目标 OS 不同时 → 强制文件复制 (硬链接/Windows 软链接跨系统不可移植) / When OS differs → force file copy (hardlinks/Windows symlinks are not portable across systems)
// 架构替换: 原始文件名含非目标架构时,替换为目标架构的所有常见命名变体后创建链接 / Arch replacement: when original filename contains non-target arch, replace with all common naming variants of target arch
func createCompatLinks(normPath string, origNames []string, targetOS, targetArch string) {
	normBase := filepath.Base(normPath)
	dir := filepath.Dir(normPath)
	// 判断是否跨平台部署 (当前系统 OS ≠ 目标 OS) / Determine cross-platform deployment (current system OS ≠ target OS)
	curOS := runtime.GOOS
	isCrossPlatform := curOS != targetOS
	targetArchNorm := normalizeArch(targetArch)

	// createOne 创建单个兼容链接 (内部函数,复用逻辑) / createOne creates a single compat link (inner function, reuses logic)
	createOne := func(linkName string) {
		if linkName == normBase {
			return
		}
		linkPath := filepath.Join(dir, linkName)
		// 如果已存在且不是链接,跳过 (避免覆盖真实文件) / Skip if exists and is not a link (avoid overwriting real files)
		if fi, err := os.Lstat(linkPath); err == nil {
			if fi.Mode()&os.ModeSymlink == 0 && fi.Size() > 0 {
				return
			}
			os.Remove(linkPath)
		}
		if isCrossPlatform {
			// 跨平台部署:直接用文件复制,确保目标系统可用 / Cross-platform deployment: always copy to ensure target system compatibility
			if err := copyFile(normPath, linkPath); err == nil {
				fmt.Fprintf(os.Stderr, "%s\n", T("link_copy", linkName, normBase))
				return
			}
			fmt.Fprintf(os.Stderr, "%s\n", T("link_fail", linkName, fmt.Errorf("copy failed")))
		} else {
			// 同平台:软链接 → 硬链接 → 复制 (效率优先) / Same platform: symlink → hardlink → copy (efficiency first)
			if err := os.Symlink(normBase, linkPath); err == nil {
				fmt.Fprintf(os.Stderr, "%s\n", T("link_symlink", linkName, normBase))
				return
			}
			if err := os.Link(normPath, linkPath); err == nil {
				fmt.Fprintf(os.Stderr, "%s\n", T("link_hardlink", linkName, normBase))
				return
			}
			if err := copyFile(normPath, linkPath); err == nil {
				fmt.Fprintf(os.Stderr, "%s\n", T("link_copy", linkName, normBase))
				return
			}
			fmt.Fprintf(os.Stderr, "%s\n", T("link_fail", linkName, fmt.Errorf("all methods failed")))
		}
	}

	for _, orig := range origNames {
		if orig == normBase {
			continue
		}
		// 检查原始文件名中的架构关键词 / Check arch keyword in original filename
		origArch, hasArch := extractArchFromName(orig)
		if !hasArch {
			// 无架构关键词,直接创建链接 / No arch keyword, create link directly
			createOne(orig)
			continue
		}
		if origArch == targetArchNorm {
			// 架构匹配,直接创建链接 / Arch matches, create link directly
			createOne(orig)
			continue
		}
		// 架构不符:替换为目标架构的所有常见命名变体 / Arch mismatch: replace with all common naming variants of target arch
		variants := generateArchVariants(orig, origArch, targetArchNorm)
		for _, v := range variants {
			fmt.Fprintf(os.Stderr, "%s\n", T("link_arch_replace", orig, v, origArch, targetArchNorm))
			createOne(v)
		}
	}
}

// extractArchFromName 从文件名中提取架构关键词,返回 (原始关键词, 归一化架构, 是否找到) / extractArchFromName extracts architecture keyword from filename, returns (raw keyword, normalized arch, found)
// 例如 libfoo_x86_64.so → ("x86_64", "x86_64", true), libfoo.so → ("", "", false) / e.g. libfoo_x86_64.so → ("x86_64", "x86_64", true), libfoo.so → ("", "", false)
func extractArchFromName(fileName string) (string, bool) {
	lower := strings.ToLower(fileName)
	// 按长度降序排列,避免短关键词先匹配 (如 arm 匹配到 aarch64 中的子串) / Sort by length descending to avoid short keywords matching substrings (e.g. arm matching inside aarch64)
	archKeywords := []string{
		"aarch_64", "aarch64", "aarch_", "aarch",
		"loongarch64", "loongarch32", "loongarch",
		"x86_64", "x86_", "x86",
		"arm64", "arm_64", "armv7", "arm",
		"amd64", "riscv64", "riscv32", "riscv",
		"sparc64", "sparc", "ppc64", "ppc",
		"s390x", "s390", "mips64", "mips",
		"i386", "i686",
	}
	for _, kw := range archKeywords {
		if strings.Contains(lower, kw) {
			return normalizeArch(kw), true
		}
	}
	return "", false
}

// archKeywordVariants 返回某个归一化架构的所有常见命名变体 (用于文件名替换) / archKeywordVariants returns all common naming variants of a normalized arch (for filename replacement)
// 不同库的命名风格不同: netty 用 aarch_64, 通用用 aarch64, Apple 用 arm64 / Different libraries use different naming styles: netty uses aarch_64, generic uses aarch64, Apple uses arm64
func archKeywordVariants(archNorm string) []string {
	switch archNorm {
	case "aarch64":
		return []string{"aarch64", "aarch_64", "arm64"}
	case "x86_64":
		return []string{"x86_64", "amd64", "x64"}
	case "i386":
		return []string{"i386", "i686", "x86"}
	case "arm":
		return []string{"arm", "armv7"}
	case "riscv64":
		return []string{"riscv64"}
	case "riscv32":
		return []string{"riscv32"}
	case "ppc64":
		return []string{"ppc64", "ppc64le"}
	case "s390x":
		return []string{"s390x"}
	case "loongarch64":
		return []string{"loongarch64"}
	case "mips64":
		return []string{"mips64"}
	case "mips":
		return []string{"mips"}
	default:
		return []string{archNorm}
	}
}

// generateArchVariants 将文件名中的原始架构关键词替换为目标架构的所有变体 / generateArchVariants replaces the original arch keyword in filename with all variants of the target arch
// 例如 generateArchVariants("libfoo_x86_64.so", "x86_64", "aarch64") → ["libfoo_aarch64.so", "libfoo_aarch_64.so", "libfoo_arm64.so"] / e.g. generateArchVariants("libfoo_x86_64.so", "x86_64", "aarch64") → ["libfoo_aarch64.so", "libfoo_aarch_64.so", "libfoo_arm64.so"]
func generateArchVariants(origName, fromArchNorm, toArchNorm string) []string {
	lower := strings.ToLower(origName)
	// 找到原始架构的所有变体关键词 / Find all variant keywords of the original arch
	fromVariants := archKeywordVariants(fromArchNorm)
	// 找到目标架构的所有变体关键词 / Find all variant keywords of the target arch
	toVariants := archKeywordVariants(toArchNorm)

	// 确定实际匹配到的原始关键词 (可能是变体之一) / Determine the actually matched original keyword (could be one of the variants)
	matchedKW := ""
	for _, v := range fromVariants {
		if strings.Contains(lower, v) {
			matchedKW = v
			break
		}
	}
	if matchedKW == "" {
		return nil
	}

	// 替换为每个目标变体,去重 / Replace with each target variant, deduplicated
	seen := map[string]bool{}
	var results []string
	for _, toKW := range toVariants {
		newName := strings.ReplaceAll(origName, matchedKW, toKW)
		// 保持原始大小写风格 (文件名可能是混合大小写) / Preserve original case style (filename might be mixed case)
		if matchedKW != strings.ToLower(matchedKW) {
			// 原始关键词含大写,用 ToLower 替换后再处理 / Original keyword has uppercase, replace then handle
			newName = strings.ReplaceAll(strings.ToLower(origName), strings.ToLower(matchedKW), toKW)
		}
		if !seen[newName] {
			seen[newName] = true
			results = append(results, newName)
		}
	}
	return results
}

// cacheJarRoot 返回 jar 缓存目录的绝对路径 (当前目录下的 .jarCache) / cacheJarRoot returns the absolute path of the jar cache directory (.jarCache under current dir)
func cacheJarRoot() string {
	wd, _ := os.Getwd()
	return filepath.Join(wd, ".jarCache")
}

// ensureCacheDir 创建缓存目录 (如不存在) / ensureCacheDir creates the cache directory if it does not exist
func ensureCacheDir() error {
	return os.MkdirAll(cacheJarRoot(), 0755)
}

// cachePathForJar 根据 Maven 坐标和 jar 文件名计算缓存路径 (Maven 本地仓库目录结构) / cachePathForJar computes the cache path based on Maven coordinates and jar filename (Maven local repo layout)
// 目录结构: .jarCache/group/id/artifactId/version/artifactId-version-classifier.jar / Dir structure: .jarCache/group/id/artifactId/version/artifactId-version-classifier.jar
func cachePathForJar(coord MavenCoord, jarFileName string) string {
	groupPath := strings.ReplaceAll(coord.GroupID, ".", string(filepath.Separator))
	return filepath.Join(cacheJarRoot(), groupPath, coord.ArtifactID, coord.Version, jarFileName)
}

// jarFileNameFromURL 从 Maven URL 中提取 jar 文件名 / jarFileNameFromURL extracts the jar filename from a Maven URL
func jarFileNameFromURL(url string) string {
	// 取最后一个 "/" 之后的部分 / Take the part after the last "/"
	i := strings.LastIndex(url, "/")
	if i < 0 {
		return url
	}
	return url[i+1:]
}

// extractSOFromJar 从 jar 文件(本地路径)中提取匹配目标架构的本地库到 dst / extractSOFromJar extracts the native library matching target architecture from a local jar file to dst
func extractSOFromJar(jarPath, dst, targetArch, libName string) error {
	zr, err := zip.OpenReader(jarPath)
	if err != nil {
		return fmt.Errorf(T("open_failed"), jarPath, err)
	}
	defer zr.Close()
	targetArchNorm := normalizeArch(targetArch)
	var bestMatch *zip.File
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !isNativeEntry(f.Name) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		head := make([]byte, 1024*1024)
		n, err := io.ReadFull(rc, head)
		rc.Close()
		if err != nil && err != io.ErrUnexpectedEOF {
			continue
		}
		head = head[:n]
		_, archs := detectBinaryArch(head, int64(f.UncompressedSize64))
		for _, a := range archs {
			if normalizeArch(a) == targetArchNorm {
				bestMatch = f
				break
			}
		}
		if bestMatch != nil {
			break
		}
	}
	if bestMatch == nil {
		return fmt.Errorf("jar 内未找到 %s 架构的 %s", targetArch, libName)
	}
	rc, err := bestMatch.Open()
	if err != nil {
		return fmt.Errorf("打开 jar 内条目失败: %v", err)
	}
	defer rc.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, rc); err != nil {
		out.Close()
		return err
	}
	out.Close()
	return nil
}

// downloadFile 下载 URL 到 dst 路径,先写临时文件再 rename 原子替换 / downloadFile downloads a URL to the dst path, writes to a temp file first, then atomically renames
func downloadFile(client *http.Client, url, dst string) error {
	tmp := dst + ".part"
	os.Remove(tmp)
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, resp.Body); err != nil {
		out.Close()
		return err
	}
	out.Close()
	return os.Rename(tmp, dst)
}

// downloadJarAndExtractSO 下载 jar 包并从中提取匹配目标架构的 .so/.dylib/.dll 文件 / downloadJarAndExtractSO downloads a jar and extracts the .so/.dylib/.dll file matching the target architecture from it
// 流程: 下载 jar 到临时文件 → 打开 zip → 遍历条目找本地库 → 检查架构是否匹配 → 提取到 dst / Flow: download jar to temp file → open zip → traverse entries to find native library → check architecture match → extract to dst
func downloadJarAndExtractSO(client *http.Client, url, dst, targetArch, libName string) error {
	// 1. 下载 jar 到临时文件 / 1. Download jar to a temp file
	tmpJar := dst + ".jar.tmp"
	defer os.Remove(tmpJar)
	if err := downloadFile(client, url, tmpJar); err != nil {
		return err
	}
	// 2. 打开 jar 为 zip / 2. Open the jar as a zip
	zr, err := zip.OpenReader(tmpJar)
	if err != nil {
		return fmt.Errorf(T("open_failed"), "downloaded jar", err)
	}
	defer zr.Close()
	// 3. 遍历条目,找匹配目标架构的本地库 / 3. Traverse entries to find the native library matching the target architecture
	targetArchNorm := normalizeArch(targetArch)
	var bestMatch *zip.File
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !isNativeEntry(f.Name) {
			continue
		}
		// 读取文件头解析架构 / Read the file header to parse architecture
		rc, err := f.Open()
		if err != nil {
			continue
		}
		head := make([]byte, 1024*1024)
		n, err := io.ReadFull(rc, head)
		rc.Close()
		if err != nil && err != io.ErrUnexpectedEOF {
			continue
		}
		head = head[:n]
		_, archs := detectBinaryArch(head, int64(f.UncompressedSize64))
		// 归一化架构名后比较 / Compare after normalizing architecture names
		for _, a := range archs {
			if normalizeArch(a) == targetArchNorm {
				bestMatch = f
				break
			}
		}
		if bestMatch != nil {
			break
		}
	}
	if bestMatch == nil {
		return fmt.Errorf("jar 内未找到 %s 架构的 %s", targetArch, libName)
	}
	// 4. 提取匹配的文件到 dst / 4. Extract the matched file to dst
	rc, err := bestMatch.Open()
	if err != nil {
		return fmt.Errorf("打开 jar 内条目失败: %v", err)
	}
	defer rc.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, rc); err != nil {
		out.Close()
		return err
	}
	out.Close()
	return nil
}

// scanDownloadedFile 扫描下载的文件,返回格式和架构信息字符串 / scanDownloadedFile scans a downloaded file, returns a string of format and architecture info
func scanDownloadedFile(path string, fileSize int64) string {
	f, err := os.Open(path)
	if err != nil {
		return T("cannot_read")
	}
	defer f.Close()
	head := make([]byte, 1024*1024)
	n, err := io.ReadFull(f, head)
	if err != nil && err != io.ErrUnexpectedEOF {
		return T("cannot_read_header")
	}
	head = head[:n]
	format, archs := detectBinaryArch(head, fileSize)
	// 归一化架构名 / Normalize architecture names
	for i, a := range archs {
		archs[i] = normalizeArch(a)
	}
	formatCN := formatDesc(format)
	if len(archs) == 0 {
		return T("format_arch", formatCN)
	}
	return T("format_arch_list", formatCN, strings.Join(archs, "、"))
}

// maskPath 脱敏路径:将用户主目录替换为 ~,隐藏电脑账号等信息 / maskPath masks paths: replaces the user's home directory with ~, hiding computer account info etc.
func maskPath(p string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return p
	}
	if strings.HasPrefix(p, home) {
		return "~" + p[len(home):]
	}
	return p
}

// runtimeOS 抽成函数便于后续 mock 测试 / runtimeOS extracted as a function to facilitate later mock testing
func runtimeOS() string {
	return runtime.GOOS
}
func runtimeArch() string {
	return runtime.GOARCH
}

// =====================================================
//
//	输出 (含本地架构信息) / Output (including native architecture info)
//
// =====================================================

// formatWithChinese 为二进制格式添加中文说明 / formatWithChinese adds Chinese descriptions for binary formats
func formatWithChinese(format string) string {
	switch format {
	case "ELF":
		return "ELF (Linux/BSD 可执行文件)"
	case "Mach-O":
		return "Mach-O (macOS/iOS 可执行文件)"
	case "PE":
		return "PE (Windows 可执行文件)"
	case "Archive(.a)":
		return "Archive(.a) (Unix 静态库)"
	case "XCOFF":
		return "XCOFF (AIX 可执行文件)"
	default:
		return format + " (未知格式)"
	}
}

// archWithChinese 为 CPU 架构添加中文说明 / archWithChinese adds Chinese descriptions for CPU architectures
func archWithChinese(arch string) string {
	switch arch {
	case "i386":
		return "i386 (Intel 32位)"
	case "x86":
		return "x86 (Intel 32位)"
	case "x86_64":
		return "x86_64 (Intel 64位)"
	case "x86_64 (AMD64)":
		return "x86_64 (AMD64, Intel 64位)"
	case "arm":
		return "arm (ARM 32位)"
	case "armv7":
		return "armv7 (ARM v7 32位)"
	case "aarch64":
		return "aarch64 (ARM 64位)"
	case "arm64":
		return "arm64 (ARM 64位)"
	case "arm64_ilp32":
		return "arm64_ilp32 (ARM 64位 ILP32模式)"
	case "mips":
		return "mips (MIPS 32位)"
	case "mips64":
		return "mips64 (MIPS 64位)"
	case "riscv32":
		return "riscv32 (RISC-V 32位)"
	case "riscv64":
		return "riscv64 (RISC-V 64位)"
	case "sparc":
		return "sparc (SPARC 32位)"
	case "sparc64":
		return "sparc64 (SPARC 64位)"
	case "ppc":
		return "ppc (PowerPC 32位)"
	case "ppc64":
		return "ppc64 (PowerPC 64位)"
	case "s390x":
		return "s390x (IBM System/390 64位)"
	case "s390":
		return "s390 (IBM System/390 32位)"
	case "ia64":
		return "ia64 (Intel Itanium 64位)"
	case "loongarch32":
		return "loongarch32 (龙芯 32位)"
	case "loongarch64":
		return "loongarch64 (龙芯 64位)"
	default:
		return arch
	}
}

// archTagWithChinese 将架构列表拼接为带中文说明的标签 (用 + 分隔,用于详细列表) / archTagWithChinese concatenates the architecture list into a tag with Chinese descriptions (separated by +, for detailed lists)
func archTagWithChinese(archs []string) string {
	if len(archs) == 0 {
		return "?"
	}
	parts := make([]string, 0, len(archs))
	for _, a := range archs {
		parts = append(parts, archWithChinese(a))
	}
	return strings.Join(parts, " + ")
}

// archTagShort 将架构列表拼接为简写标签 (用、分隔,只保留架构名,用于概览) / archTagShort concatenates the architecture list into a short tag (separated by 、, only keeps architecture names, for overview)
func archTagShort(archs []string) string {
	if len(archs) == 0 {
		return "?"
	}
	// 架构名简写映射 / Architecture name abbreviation mapping
	shortMap := map[string]string{
		"i386":           "i386",
		"x86":            "x86",
		"x86_64":         "x86_64",
		"x86_64 (AMD64)": "x86_64",
		"arm":            "arm",
		"armv7":          "armv7",
		"aarch64":        "aarch64",
		"arm64":          "arm64",
		"arm64_ilp32":    "arm64_ilp32",
		"mips":           "mips",
		"mips64":         "mips64",
		"riscv32":        "riscv32",
		"riscv64":        "riscv64",
		"sparc":          "sparc",
		"sparc64":        "sparc64",
		"ppc":            "ppc",
		"ppc64":          "ppc64",
		"s390x":          "s390x",
		"s390":           "s390",
		"ia64":           "ia64",
		"loongarch32":    "loongarch32",
		"loongarch64":    "loongarch64",
	}
	parts := make([]string, 0, len(archs))
	for _, a := range archs {
		if s, ok := shortMap[a]; ok {
			parts = append(parts, s)
		} else {
			parts = append(parts, a)
		}
	}
	return strings.Join(parts, "、")
}

// =====================================================
//
//	架构缺失分析 / Architecture gap analysis
//
// =====================================================

// ArchGap 表示某个平台上某个本地库缺失的架构 / ArchGap represents the missing architectures of a native library on a certain platform
type ArchGap struct {
	Platform     string
	FormatCN     string
	LibraryFile  string   // 本地库文件名,如 libsnappyjava.so / Native library filename, e.g. libsnappyjava.so
	HaveArchs    []string // 已支持的架构 / Supported architectures
	MissingArchs []string // 缺失的架构 (相对于同平台其他库的完整架构集) / Missing architectures (relative to the complete architecture set of other libraries on the same platform)
}

// normalizeLibraryName 从文件名中提取库的"基础名",用于合并同一库的不同架构文件 / normalizeLibraryName extracts the library's "base name" from the filename, used to merge different architecture files of the same library
// 例如: / e.g.:
//
//	libsnappyjava.dylib + libsnappyjava.jnilib → libsnappyjava.dylib
//	netty_tcnative_osx_.jnilib + netty_tcnative_osx_aarch_.jnilib → netty_tcnative.dylib
func normalizeLibraryName(fileName string) string {
	// 1. 统一扩展名: .jnilib 和 .dylib 都是 macOS 动态库,归一化为 .dylib / 1. Unify extensions: .jnilib and .dylib are both macOS dynamic libraries, normalize to .dylib
	ext := strings.ToLower(filepath.Ext(fileName))
	if ext == ".jnilib" {
		ext = ".dylib"
	}
	base := strings.TrimSuffix(fileName, filepath.Ext(fileName))

	// 2. 转小写处理 / 2. Convert to lowercase
	base = strings.ToLower(base)

	// 3. 去掉文件名中所有架构关键词 (可能在中间,如 osx_aarch_) / 3. Remove all architecture keywords from the filename (may be in the middle, e.g. osx_aarch_)
	// 按长度降序排列,避免短关键词先匹配导致残留 / Sort by length in descending order to avoid short keywords matching first and leaving residue
	archKeywords := []string{
		"aarch_64", "aarch64", "aarch_", "aarch",
		"loongarch64", "loongarch32", "loongarch",
		"x86_64", "x86_", "x86",
		"arm64", "arm_64", "armv7", "arm",
		"amd64", "riscv64", "riscv32", "riscv",
		"sparc64", "sparc", "ppc64", "ppc",
		"s390x", "s390", "mips64", "mips",
		"i386", "i686",
		"_64", "_32",
		"64", "32",
	}
	for _, kw := range archKeywords {
		base = strings.ReplaceAll(base, kw, "")
	}

	// 4. 去掉平台关键词 / 4. Remove platform keywords
	platformKeywords := []string{
		"linux", "windows", "win32", "win64", "win",
		"macosx", "darwin", "osx", "mac",
		"sunos", "aix",
	}
	for _, kw := range platformKeywords {
		base = strings.ReplaceAll(base, kw, "")
	}

	// 5. 清理多余的分隔符: 连续的 _ 或尾部 _ / 5. Clean up extra separators: consecutive _ or trailing _
	for strings.Contains(base, "__") {
		base = strings.ReplaceAll(base, "__", "_")
	}
	base = strings.Trim(base, "_-.")

	return base + ext
}

// analyzeArchGaps 分析本地库的架构缺失情况 / analyzeArchGaps analyzes the architecture gaps of native libraries
// 对每个平台,先统计所有本地库支持的架构并集作为"完整架构集", / For each platform, first compute the union of architectures supported by all native libraries as the "complete architecture set",
// 然后检查每个库在该平台上缺失了哪些架构。 / Then check which architectures each library is missing on that platform.
// 例如:snappy-java 在 Linux 支持 x86_64+i386,leveldbjni 在 Linux 只支持 x86_64, / e.g.: snappy-java supports x86_64+i386 on Linux, leveldbjni only supports x86_64 on Linux,
// 则 leveldbjni 被标记为"Linux i386 架构缺失"。 / Then leveldbjni is marked as "Linux i386 architecture missing".
func analyzeArchGaps(artifacts []NativeArtifact) []ArchGap {
	// 1. 按平台分组,计算每个平台的完整架构集 / 1. Group by platform, compute the complete architecture set for each platform
	platformArchs := map[string]map[string]struct{}{}
	for _, a := range artifacts {
		if a.Platform == "" || a.Platform == "未知" {
			continue
		}
		if platformArchs[a.Platform] == nil {
			platformArchs[a.Platform] = map[string]struct{}{}
		}
		for _, arch := range a.Archs {
			if arch != "" {
				platformArchs[a.Platform][arch] = struct{}{}
			}
		}
	}

	// 2. 按平台 + 归一化库 key 分组,合并同一库的架构(如 Fat Binary 或多架构文件) / 2. Group by platform + normalized library key, merge architectures of the same library (e.g. Fat Binary or multi-architecture files)
	// 用 normalizeLibKey 做分组 key:去掉 lib 前缀、版本号、架构/平台关键词, / Use normalizeLibKey as the grouping key: remove lib prefix, version numbers, architecture/platform keywords,
	// 让 libsnappyjava.so 与 snappyjava.so、libzstd-jni-1.5.5-5.so 与 zstd-jni.so 合并。 / So libsnappyjava.so and snappyjava.so, libzstd-jni-1.5.5-5.so and zstd-jni.so are merged.
	// 与 overlay 命令复用同一个 normalizeLibKey,确保两侧合并口径一致。 / Reuse the same normalizeLibKey with the overlay command to ensure consistent merge semantics on both sides.
	// 展示名单独保留 normalizeLibraryName 的结果(保留 lib 前缀,更接近原文件名)。 / The display name separately keeps the result of normalizeLibraryName (keeps the lib prefix, closer to the original filename).
	type key struct{ Platform, LibKey string }
	groupArchs := map[key]map[string]struct{}{}
	groupFormat := map[key]string{}
	groupDisplay := map[key]string{}
	for _, a := range artifacts {
		if a.Platform == "" || a.Platform == "未知" {
			continue
		}
		libFile := filepath.Base(a.Path)
		libKey := normalizeLibKey(libFile)
		k := key{a.Platform, libKey}
		if groupArchs[k] == nil {
			groupArchs[k] = map[string]struct{}{}
			groupDisplay[k] = normalizeLibraryName(libFile)
		}
		for _, arch := range a.Archs {
			if arch != "" {
				groupArchs[k][arch] = struct{}{}
			}
		}
		groupFormat[k] = a.Format
	}

	// 3. 找出每个库的缺失架构 / 3. Find the missing architectures for each library
	var gaps []ArchGap
	for k, archSet := range groupArchs {
		fullSet := platformArchs[k.Platform]

		haveArchs := make([]string, 0, len(archSet))
		for arch := range archSet {
			haveArchs = append(haveArchs, arch)
		}
		sort.Strings(haveArchs)

		var missingArchs []string
		for arch := range fullSet {
			if _, ok := archSet[arch]; !ok {
				missingArchs = append(missingArchs, arch)
			}
		}
		sort.Strings(missingArchs)

		if len(missingArchs) > 0 {
			gaps = append(gaps, ArchGap{
				Platform:     k.Platform,
				FormatCN:     formatDesc(groupFormat[k]),
				LibraryFile:  groupDisplay[k],
				HaveArchs:    haveArchs,
				MissingArchs: missingArchs,
			})
		}
	}

	// 4. 按平台 + 文件名排序输出 / 4. Sort output by platform + filename
	sort.Slice(gaps, func(i, j int) bool {
		if gaps[i].Platform != gaps[j].Platform {
			return gaps[i].Platform < gaps[j].Platform
		}
		return gaps[i].LibraryFile < gaps[j].LibraryFile
	})

	return gaps
}

func printResult(title string, libs []types.Library, deps []types.Dependency, ns *ScanResult) {
	fmt.Printf("=== %s ===\n", title)

	// --- 本地架构产物 (仅 jar 模式会传 ns) --- / --- Native architecture artifacts (only jar mode passes ns) ---
	if ns != nil {
		if ns.HasNative {
			fmt.Printf("\n%s\n", T("cclib_header", ns.NativeCount))
			fmt.Printf("  %s\n", T("platforms", ns.Platforms))
			fmt.Printf("  %s\n", T("archs", ns.Archs))
			for _, a := range ns.Artifacts {
				fmt.Printf("    - %-40s  fmt=%s  arch=%s  size=%d\n",
					shortPath(a.Path, 40), formatDesc(a.Format), archTagDesc(a.Archs), a.FileSize)
			}

			// --- 架构缺失分析 --- / --- Architecture gap analysis ---
			gaps := analyzeArchGaps(ns.Artifacts)

			// 先打印各平台支持的架构总览 (用简写+、分隔,换行显示) / First print the overview of architectures supported by each platform (using abbreviation + 、 separator, displayed on a new line)
			fmt.Println()
			fmt.Println("  " + T("overview"))
			platformArchsMap := map[string]map[string]struct{}{}
			platformFormatMap := map[string]string{}
			for _, a := range ns.Artifacts {
				if a.Platform == "" || a.Platform == "未知" {
					continue
				}
				if platformArchsMap[a.Platform] == nil {
					platformArchsMap[a.Platform] = map[string]struct{}{}
				}
				for _, arch := range a.Archs {
					if arch != "" {
						platformArchsMap[a.Platform][arch] = struct{}{}
					}
				}
				platformFormatMap[a.Platform] = a.Format
			}
			platforms := make([]string, 0, len(platformArchsMap))
			for p := range platformArchsMap {
				platforms = append(platforms, p)
			}
			sort.Strings(platforms)
			for _, p := range platforms {
				archSet := platformArchsMap[p]
				archs := make([]string, 0, len(archSet))
				for arch := range archSet {
					archs = append(archs, arch)
				}
				sort.Strings(archs)
				fmt.Printf("  %s (%s):\n", p, formatDesc(platformFormatMap[p]))
				fmt.Printf("    [%s]\n", archTagShort(archs))
			}

			if len(gaps) > 0 {
				fmt.Println()
				fmt.Println("  " + T("gap_analysis"))
				currentPlatform := ""
				for _, g := range gaps {
					if g.Platform != currentPlatform {
						if currentPlatform != "" {
							fmt.Println()
						}
						fmt.Printf("  %s (%s):\n", g.Platform, g.FormatCN)
						currentPlatform = g.Platform
					}
					fmt.Printf("    %s\n", T("gap_missing",
						g.LibraryFile,
						archTagShort(g.HaveArchs),
						archTagShort(g.MissingArchs)))
				}
				fmt.Println()
				fmt.Printf("  %s\n", T("gap_total", len(gaps)))
				fmt.Println()
			} else {
				fmt.Println()
				fmt.Println("  " + T("gap_complete"))
				fmt.Println()
				fmt.Println("  " + T("gap_coverage"))
				for _, p := range platforms {
					archSet := platformArchsMap[p]
					archs := make([]string, 0, len(archSet))
					for arch := range archSet {
						archs = append(archs, arch)
					}
					sort.Strings(archs)
					if len(archs) > 0 {
						fmt.Printf("    %s\n", T("gap_coverage_item", p, len(archs), archTagShort(archs)))
					}
				}
				fmt.Println()
			}
		} else {
			fmt.Printf("\n%s\n\n", T("cclib_no_native"))
		}
	}

	// --- 库列表 --- / --- Library list ---
	// 用 map 按 FilePath 分组,避免重复打印相同的 jar 路径 / Group by FilePath using a map, to avoid repeatedly printing the same jar path
	// key 为 FilePath (空串归到 "" 这一组),value 为该路径下的所有库 / key is FilePath (empty string goes to the "" group), value is all libraries under that path
	groups := map[string][]types.Library{}
	for _, lib := range libs {
		groups[lib.FilePath] = append(groups[lib.FilePath], lib)
	}

	fmt.Printf("%s\n", T("libs_header", len(libs), len(groups)))
	for path, groupLibs := range groups {
		// 标题:该目录下的所有 jar 依赖库 / Title: all jar dependency libraries under this directory
		if path == "" {
			fmt.Printf("\n%s\n", T("libs_unknown", len(groupLibs)))
		} else {
			fmt.Printf("\n%s\n", T("libs_jar", path, len(groupLibs)))
		}
		for _, lib := range groupLibs {
			indirect := ""
			if lib.Indirect {
				indirect = T("libs_indirect")
			}
			fmt.Printf("  - %s:%s%s", lib.Name, lib.Version, indirect)
			if lib.License != "" {
				fmt.Printf("  [license: %s]", lib.License)
			}
			fmt.Println()
		}
	}

	// --- 依赖关系 --- / --- Dependency relationships ---
	fmt.Printf("\n%s\n", T("deps_header", len(deps)))
	for _, d := range deps {
		if len(d.DependsOn) == 0 {
			continue
		}
		fmt.Printf("  %s -> %v\n", d.ID, d.DependsOn)
	}
}

// shortPath 把长路径截断,宽度为 w;前缀保留到最后一个 / 之前,中间省略号 / shortPath truncates long paths to width w; keeps the prefix up to the last /, with an ellipsis in the middle
func shortPath(p string, w int) string {
	if len(p) <= w {
		return p
	}
	dir := filepath.Dir(p)
	base := filepath.Base(p)
	// "dirname/.../basename"
	mid := "..."
	wantDir := w - len(mid) - len(base) - 1
	if wantDir <= 0 {
		// 实在放不下,直接省略开头 / Really can't fit, omit the beginning directly
		return "..." + p[len(p)-w+3:]
	}
	if len(dir) > wantDir {
		dir = dir[:wantDir]
	}
	return dir + "/" + mid + "/" + base
}

// =====================================================
//  jar 扫描: 识别 C/C++ 本地二进制 + 架构 / jar scan: identify C/C++ native binaries + architectures
//  支持两种 fat jar 格式: / Supports two fat jar formats:
//    1. maven-assembly "with-dependencies": 依赖被解压平铺进主 jar /    1. maven-assembly "with-dependencies": dependencies are unzipped and flattened into the main jar
//    2. Spring Boot / WAR / EAR: 依赖作为嵌套 jar 存在 (BOOT-INF/lib/*.jar 等) /    2. Spring Boot / WAR / EAR: dependencies exist as nested jars (BOOT-INF/lib/*.jar etc.)
//  通过递归扫描嵌套 jar 同时覆盖两种场景。 / By recursively scanning nested jars, both scenarios are covered.
// =====================================================

const (
	maxNestDepth     = 5         // 最大递归深度,防止恶意 zip 炸弹 / Maximum recursion depth, to prevent malicious zip bombs
	maxNestedJarSize = 200 << 20 // 单个嵌套 jar 最大 200MB,防止内存爆炸 / Maximum 200MB per nested jar, to prevent memory explosion
)

// nativeSuffixes 认定为本地二进制的文件后缀 / nativeSuffixes file suffixes recognized as native binaries
// JNI 常见约定目录名: lib/linux-x86_64/、META-INF/native/、native/、osx/ 等 / JNI common convention directory names: lib/linux-x86_64/, META-INF/native/, native/, osx/, etc.
var nativeSuffixes = []string{
	".so", // Linux / Android
	".so.1", ".so.2", ".so.3",
	".dylib",  // macOS
	".jnilib", // macOS JNI 老约定 / macOS JNI old convention
	".dll",    // Windows
	".a",      // Unix 静态库 (ar archive) / Unix static library (ar archive)
	".lib",    // Windows 静态库/导入库 / Windows static library / import library
}

func isNativeEntry(name string) bool {
	lower := strings.ToLower(name)
	for _, suf := range nativeSuffixes {
		if strings.HasSuffix(lower, suf) {
			return true
		}
	}
	return false
}

// scanJarNativeArtifacts 入口:打开主 jar 文件并启动递归扫描 / scanJarNativeArtifacts entry: opens the main jar file and starts recursive scanning
func scanJarNativeArtifacts(jarPath string) ScanResult {
	zr, err := zip.OpenReader(jarPath)
	if err != nil {
		// 打不开就直接返回空,不影响主流程 / If it can't be opened, return empty directly, doesn't affect the main flow
		return ScanResult{}
	}
	defer zr.Close()

	result := &ScanResult{}
	// 主 jar 用文件名作为路径前缀,嵌套 jar 后续会追加 "!" 分隔符 / The main jar uses the filename as the path prefix; nested jars will append "!" separator later
	scanZipFiles(zr.File, filepath.Base(jarPath), result, 0, MavenCoord{}, "")

	// 统一聚合平台/架构集合 / Unify and aggregate platform/architecture sets
	result.NativeCount = len(result.Artifacts)
	result.HasNative = result.NativeCount > 0
	platSet := map[string]struct{}{}
	archSet := map[string]struct{}{}
	for _, a := range result.Artifacts {
		if a.Platform != "" && a.Platform != "未知" {
			platSet[a.Platform] = struct{}{}
		}
		for _, arch := range a.Archs {
			if arch != "" {
				archSet[arch] = struct{}{}
			}
		}
	}
	result.Platforms = sortedKeys(platSet)
	result.Archs = sortedKeys(archSet)
	return *result
}

// scanZipFiles 递归遍历 zip 条目: / scanZipFiles recursively traverses zip entries:
//   - 后缀为 .so/.dll/.dylib/.a/.lib 等 → 识别为本地二进制并解析架构 /   - Suffix is .so/.dll/.dylib/.a/.lib etc. → recognized as native binary and architecture is parsed
//   - 后缀为 .jar → 解压到内存,用 zip.NewReader 打开后递归扫描 /   - Suffix is .jar → extracted to memory, opened with zip.NewReader, then recursively scanned
//
// prefix 是显示用的"路径前缀",形如 "app.jar!BOOT-INF/lib/snappy-java-1.0.4.1.jar" / prefix is the "path prefix" for display, e.g. "app.jar!BOOT-INF/lib/snappy-java-1.0.4.1.jar"
// coord 和 jarName 是当前 jar 的 Maven 坐标和文件名 (主 jar 传空值,嵌套 jar 传入从 pom.properties 解析的坐标) / coord and jarName are the Maven coordinates and filename of the current jar (main jar passes empty values; nested jars pass coordinates parsed from pom.properties)
func scanZipFiles(files []*zip.File, prefix string, result *ScanResult, depth int, coord MavenCoord, jarName string) {
	if depth > maxNestDepth {
		return
	}

	for _, fe := range files {
		if fe.FileInfo().IsDir() {
			continue
		}
		name := fe.Name
		lowerName := strings.ToLower(name)

		// (1) 本地二进制文件 / (1) Native binary file
		if isNativeEntry(name) {
			art := analyzeNativeEntry(fe, prefix+"!"+name, coord, jarName)
			result.Artifacts = append(result.Artifacts, art)
			continue
		}

		// (2) 嵌套 jar (Spring Boot BOOT-INF/lib/*.jar / WAR WEB-INF/lib/*.jar / EAR lib/*.jar) / (2) Nested jar (Spring Boot BOOT-INF/lib/*.jar / WAR WEB-INF/lib/*.jar / EAR lib/*.jar)
		if strings.HasSuffix(lowerName, ".jar") {
			// 限制大小,防止把超大嵌套 jar 全读进内存 / Limit size to prevent reading huge nested jars entirely into memory
			if fe.UncompressedSize64 > maxNestedJarSize {
				continue
			}
			// 把嵌套 jar 条目读进内存,再用 zip.NewReader 解析 / Read the nested jar entry into memory, then parse with zip.NewReader
			rc, err := fe.Open()
			if err != nil {
				continue
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil || len(data) < 4 {
				continue
			}
			br := bytes.NewReader(data)
			zr, err := zip.NewReader(br, int64(len(data)))
			if err != nil {
				continue // 不是有效 zip,跳过 (有些 .jar 条目实际是别的格式) / Not a valid zip, skip (some .jar entries are actually other formats)
			}
			// 读取嵌套 jar 的 pom.properties,提取 Maven 坐标 / Read the nested jar's pom.properties, extract Maven coordinates
			innerCoord := parsePomPropertiesFromZip(zr.File)
			// 递归扫描,前缀加上 "outer.jar!inner.jar" 形式 / Recursive scan, prefix gets "outer.jar!inner.jar" form
			scanZipFiles(zr.File, prefix+"!"+name, result, depth+1, innerCoord, name)
		}
	}
}

// parsePomPropertiesFromZip 从 zip 文件列表中查找 META-INF/maven/*/pom.properties 并解析 Maven 坐标 / parsePomPropertiesFromZip searches for META-INF/maven/*/pom.properties in the zip file list and parses Maven coordinates
func parsePomPropertiesFromZip(files []*zip.File) MavenCoord {
	for _, f := range files {
		if f.FileInfo().IsDir() {
			continue
		}
		if !strings.HasPrefix(f.Name, "META-INF/maven/") || !strings.HasSuffix(f.Name, "/pom.properties") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}
		return parsePomProperties(data)
	}
	return MavenCoord{}
}

// parsePomProperties 解析 pom.properties 文件内容,提取 groupId/artifactId/version / parsePomProperties parses pom.properties file content, extracts groupId/artifactId/version
func parsePomProperties(data []byte) MavenCoord {
	coord := MavenCoord{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.HasPrefix(line, "groupId=") {
			coord.GroupID = strings.TrimPrefix(line, "groupId=")
		} else if strings.HasPrefix(line, "artifactId=") {
			coord.ArtifactID = strings.TrimPrefix(line, "artifactId=")
		} else if strings.HasPrefix(line, "version=") {
			coord.Version = strings.TrimPrefix(line, "version=")
		}
	}
	return coord
}

// analyzeNativeEntry 识别单个 zip 条目对应的本地库架构 / analyzeNativeEntry identifies the native library architecture corresponding to a single zip entry
// displayPath 是给用户看的完整路径(含外层 jar 前缀) / displayPath is the full path shown to the user (including the outer jar prefix)
// coord 和 jarName 是来源 jar 的 Maven 坐标和文件名,用于 overlay 下载 / coord and jarName are the Maven coordinates and filename of the source jar, used for overlay download
func analyzeNativeEntry(fe *zip.File, displayPath string, coord MavenCoord, jarName string) NativeArtifact {
	art := NativeArtifact{
		Path:          displayPath,
		FileSize:      int64(fe.UncompressedSize64),
		Format:        "Unknown",
		SourceCoord:   coord,
		SourceJarName: jarName,
	}

	// 从原始条目名粗判平台 (例如 lib/linux-x86_64/foo.so) / Roughly judge the platform from the original entry name (e.g. lib/linux-x86_64/foo.so)
	name := fe.Name
	if strings.Contains(strings.ToLower(name), "/linux") ||
		strings.HasSuffix(strings.ToLower(name), ".so") ||
		strings.Contains(strings.ToLower(name), ".so.") {
		art.Platform = "Linux"
	} else if strings.Contains(strings.ToLower(name), "/mac") ||
		strings.Contains(strings.ToLower(name), "/osx") ||
		strings.Contains(strings.ToLower(name), "/darwin") ||
		strings.HasSuffix(strings.ToLower(name), ".dylib") ||
		strings.HasSuffix(strings.ToLower(name), ".jnilib") {
		art.Platform = "macOS"
	} else if strings.Contains(strings.ToLower(name), "/win") ||
		strings.HasSuffix(strings.ToLower(name), ".dll") ||
		strings.HasSuffix(strings.ToLower(name), ".lib") {
		art.Platform = "Windows"
	} else {
		art.Platform = "未知"
	}

	// 读取条目内容的头部做二进制解析 / Read the header of the entry content for binary parsing
	rc, err := fe.Open()
	if err == nil {
		// 对静态库 .a 读取更大范围 (成员分散在整个文件里),其他格式读 1MB 足够 / For static libraries .a, read a larger range (members are scattered throughout the file); for other formats, 1MB is enough
		want := int64(1024 * 1024)
		if strings.HasSuffix(strings.ToLower(fe.Name), ".a") ||
			strings.HasSuffix(strings.ToLower(fe.Name), ".lib") {
			want = 16 * 1024 * 1024 // 16MB,覆盖大多数 .a 静态库 / 16MB, covers most .a static libraries
		}
		want = min64(want, art.FileSize)
		head := make([]byte, want)
		if _, err2 := io.ReadFull(rc, head); err2 == nil || err2 == io.ErrUnexpectedEOF {
			art.Format, art.Archs = detectBinaryArch(head, art.FileSize)
			// 归一化架构名,统一别名 (x86_64 (AMD64) → x86_64, arm64 → aarch64, x86 → i386 等) / Normalize architecture names, unify aliases (x86_64 (AMD64) → x86_64, arm64 → aarch64, x86 → i386, etc.)
			// 与 overlay 命令复用同一个 normalizeArch,确保 jar/overlay 两侧架构表示一致 / Reuse the same normalizeArch with the overlay command to ensure consistent architecture representation on both jar/overlay sides
			for i, a := range art.Archs {
				art.Archs[i] = normalizeArch(a)
			}
			// 修正之前仅靠后缀猜的平台 (现在靠文件头更可信) / Correct the platform previously guessed only by suffix (now more reliable based on the file header)
			if plat := platformFromFormat(art.Format); plat != "" {
				art.Platform = plat
			}
			// 对 .a 静态库,根据内部成员格式推断平台: / For .a static libraries, infer the platform based on the internal member format:
			//   成员是 ELF → Linux, 成员是 Mach-O → macOS /   Member is ELF → Linux, member is Mach-O → macOS
			if art.Format == "Archive(.a)" {
				formats, _ := archiveArchs(head, art.FileSize)
				for _, f := range formats {
					if plat := platformFromFormat(f); plat != "" {
						art.Platform = plat
						break
					}
				}
			}
		}
		rc.Close()
	}

	return art
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func platformFromFormat(format string) string {
	switch format {
	case "ELF":
		return "Linux"
	case "Mach-O":
		return "macOS"
	case "PE":
		return "Windows"
	case "Archive(.a)":
		// .a 在 Linux/macOS 都存在,无法从格式直接推断 / .a exists on both Linux/macOS, cannot be directly inferred from the format
		return ""
	case "XCOFF":
		return "AIX"
	default:
		return ""
	}
}

// =====================================================
//  二进制头解析 (Mach-O / ELF / PE / ar 归档) / Binary header parsing (Mach-O / ELF / PE / ar archive)
// =====================================================

// detectBinaryArch 根据文件头识别格式和架构;返回 (format, []arch) / detectBinaryArch identifies the format and architecture based on the file header; returns (format, []arch)
func detectBinaryArch(head []byte, size int64) (string, []string) {
	if size < 4 || len(head) < 4 {
		return "Unknown", nil
	}

	// ---- 1. Mach-O (macOS / iOS) ---- / ---- 1. Mach-O (macOS / iOS) ----
	// Mach-O 32-bit: 0xFEEDFACE, 64-bit: 0xFEEDFACF, reversed (little-endian): 0xCEFAEDFE/0xCFFAEDFE / Mach-O 32-bit: 0xFEEDFACE, 64-bit: 0xFEEDFACF, reversed (little-endian): 0xCEFAEDFE/0xCFFAEDFE
	// Fat Mach-O (Universal): 0xCAFEBABE or 0xBEBAFECA / Fat Mach-O (Universal): 0xCAFEBABE or 0xBEBAFECA
	magic := binary.BigEndian.Uint32(head[:4])
	switch magic {
	case 0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE:
		return "Mach-O", []string{machoArchFromMagic(head)}
	case 0xCAFEBABE, 0xBEBAFECA:
		// Fat binary: 可能含多个 slice / Fat binary: may contain multiple slices
		return "Mach-O", fatMachoArchs(head, size)
	}

	// ---- 2. ELF (Linux / BSD) ---- / ---- 2. ELF (Linux / BSD) ----
	if head[0] == 0x7F && head[1] == 'E' && head[2] == 'L' && head[3] == 'F' {
		archs, ok := elfArchs(head)
		if ok {
			return "ELF", archs
		}
		return "ELF", nil
	}

	// ---- 3. PE (Windows DLL/EXE) ---- / ---- 3. PE (Windows DLL/EXE) ----
	// PE 以 MZ 开头,随后 0x3C 处给出 PE signature 偏移;signature "PE\0\0" 后是 Machine 字段 / PE starts with MZ, then at 0x3C gives the PE signature offset; after signature "PE\0\0" is the Machine field
	if head[0] == 'M' && head[1] == 'Z' && size >= 0x40 {
		archs, ok := peArchs(head, size)
		if ok {
			return "PE", archs
		}
		return "PE", nil
	}

	// ---- 4. ar archive (Unix 静态库 .a) ---- / ---- 4. ar archive (Unix static library .a) ----
	// "!<arch>\n" 开头,随后是若干成员 (文件头58字节, 末尾为 `\n`) / Starts with "!<arch>\n", followed by several members (file header 58 bytes, ending with `\n`)
	if size >= 8 && bytes.Equal(head[:8], []byte("!<arch>\n")) {
		_, archs := archiveArchs(head, size)
		return "Archive(.a)", archs
	}

	// ---- 5. XCOFF (AIX 平台 PPC/PPC64, snappy-java 等库的 .a 文件) ---- / ---- 5. XCOFF (AIX platform PPC/PPC64, .a files of libraries like snappy-java) ----
	// XCOFF32 magic: 0x01DF, XCOFF64 magic: 0x01F7 (大端) / XCOFF32 magic: 0x01DF, XCOFF64 magic: 0x01F7 (big-endian)
	if len(head) >= 2 {
		magic := binary.BigEndian.Uint16(head[:2])
		if magic == 0x01DF {
			return "XCOFF", []string{"ppc"}
		}
		if magic == 0x01F7 {
			return "XCOFF", []string{"ppc64"}
		}
	}

	return "Unknown", nil
}

// --------- Mach-O ---------

func machoArchFromMagic(head []byte) string {
	// 找 CPU subtype 的位置: / Find the location of CPU subtype:
	//   magic:      4 bytes (offset 0) /   magic:      4 字节 (偏移 0)
	//   cputype:    4 bytes (offset 4)   (big/little endian 跟 magic 保持一致) /   cputype:    4 bytes (offset 4)   (big/little endian consistent with magic)
	//   cpusubtype: 4 bytes /   cpusubtype: 4 字节
	magicLE := binary.LittleEndian.Uint32(head[:4])
	magicBE := binary.BigEndian.Uint32(head[:4])

	var cpuType uint32
	switch magicBE {
	case 0xFEEDFACE, 0xFEEDFACF, 0xCAFEBABE:
		cpuType = binary.BigEndian.Uint32(head[4:8])
	case 0xCEFAEDFE, 0xCFFAEDFE, 0xBEBAFECA:
		cpuType = binary.LittleEndian.Uint32(head[4:8])
	default:
		// 如果 magicLE 命中也走 little endian 分支 (其实上面 switch 已经涵盖) / If magicLE matches, also go through the little endian branch (in fact, the switch above already covers it)
		switch magicLE {
		case 0xCEFAEDFE, 0xCFFAEDFE, 0xBEBAFECA:
			cpuType = binary.LittleEndian.Uint32(head[4:8])
		default:
			cpuType = binary.BigEndian.Uint32(head[4:8])
		}
	}

	return machoCPUType(cpuType)
}

// machoCPUType 参考 <mach/machine.h> / machoCPUType refers to <mach/machine.h>
func machoCPUType(cpuType uint32) string {
	const (
		CPU_ARCH_ABI64 = 0x01000000
		CPU_TYPE_X86   = 7
		CPU_TYPE_ARM   = 12
		CPU_TYPE_PPC   = 18
		CPU_TYPE_PPC64 = CPU_TYPE_PPC | CPU_ARCH_ABI64
	)
	switch cpuType {
	case CPU_TYPE_X86:
		return "i386"
	case CPU_TYPE_X86 | CPU_ARCH_ABI64:
		return "x86_64"
	case CPU_TYPE_ARM:
		return "armv7"
	case CPU_TYPE_ARM | CPU_ARCH_ABI64:
		return "arm64"
	case CPU_TYPE_PPC:
		return "ppc"
	case CPU_TYPE_PPC64:
		return "ppc64"
	default:
		return fmt.Sprintf("cpu-type-0x%x", cpuType)
	}
}

// fatMachoArchs 解析 Fat Mach-O 的每个 slice (universal binary) / fatMachoArchs parses each slice of a Fat Mach-O (universal binary)
func fatMachoArchs(head []byte, size int64) []string {
	if size < 8 || len(head) < 8 {
		return nil
	}
	be := binary.BigEndian.Uint32(head[:4]) == 0xCAFEBABE
	var narch uint32
	if be {
		narch = binary.BigEndian.Uint32(head[4:8])
	} else {
		narch = binary.LittleEndian.Uint32(head[4:8])
	}
	if narch > 64 { // 防越界 / Prevent out-of-bounds
		return nil
	}
	// 用 map 去重 (同一个 fat binary 可能含两个相同 cputype 的 slice, / Use a map to deduplicate (the same fat binary may contain two slices with the same cputype,
	// 例如 tvOS device + simulator 都是 arm64,通过 cpusubtype 区分) / e.g. tvOS device + simulator are both arm64, distinguished by cpusubtype)
	archSet := map[string]struct{}{}
	off := uint32(8) // fat_header: magic + nfat_arch / fat_header: magic + nfat_arch
	for i := uint32(0); i < narch; i++ {
		// fat_arch: cpu_type(4) cpu_subtype(4) offset(4) size(4) align(4)  = 20 bytes / fat_arch: cpu_type(4) cpu_subtype(4) offset(4) size(4) align(4)  = 20 bytes
		if len(head) < int(off)+20 {
			break
		}
		var cpuType uint32
		if be {
			cpuType = binary.BigEndian.Uint32(head[off : off+4])
		} else {
			cpuType = binary.LittleEndian.Uint32(head[off : off+4])
		}
		archSet[machoCPUType(cpuType)] = struct{}{}
		off += 20
	}
	archs := make([]string, 0, len(archSet))
	for a := range archSet {
		archs = append(archs, a)
	}
	sort.Strings(archs)
	return archs
}

// --------- ELF ---------

func elfArchs(head []byte) ([]string, bool) {
	// EI_CLASS  4th byte: 1=32, 2=64 / EI_CLASS  第 4 字节: 1=32 位, 2=64 位
	// EI_DATA   5th byte: 1=LE, 2=BE / EI_DATA   第 5 字节: 1=小端, 2=大端
	// e_machine at offset 0x12 (16-bit) / e_machine 位于偏移 0x12 (16 位)
	if len(head) < 0x14 {
		return nil, false
	}
	eiClass := head[4] // 1 = ELFCLASS32, 2 = ELFCLASS64
	data := head[5]    // EI_DATA
	var eMachine uint16
	if data == 1 {
		eMachine = binary.LittleEndian.Uint16(head[0x12:0x14])
	} else if data == 2 {
		eMachine = binary.BigEndian.Uint16(head[0x12:0x14])
	} else {
		return nil, false
	}
	name := elfMachineName(eMachine, eiClass)
	return []string{name}, true
}

// elfMachineName 根据 e_machine 和 EI_CLASS 综合给出架构名; / elfMachineName comprehensively gives the architecture name based on e_machine and EI_CLASS;
// 注意 RISC-V / MIPS / Sparc / PowerPC 的 32/64 位共用同一个 e_machine 枚举, / Note: RISC-V / MIPS / Sparc / PowerPC 32/64-bit share the same e_machine enumeration,
// 需要靠 EI_CLASS 来区分 32 vs 64。 / Need to distinguish 32 vs 64 via EI_CLASS.
func elfMachineName(m uint16, eiClass byte) string {
	is64 := eiClass == 2
	switch m {
	case 0x03:
		return "i386"
	case 0x3E:
		return "x86_64"
	case 0x28:
		if is64 {
			return "arm" // e_machine 0x28 本身就是 32-bit ARM;64-bit 走 0xB7 / e_machine 0x28 itself is 32-bit ARM; 64-bit goes through 0xB7
		}
		return "arm"
	case 0xB7:
		return "aarch64"
	case 0xB6:
		return "arm64_ilp32"
	case 0x08: // EM_MIPS = 8 (MIPS I 架构定义 32-bit;历史上 64-bit 也复用) / EM_MIPS = 8 (MIPS I architecture defines 32-bit; historically 64-bit also reuses it)
		if is64 {
			return "mips64"
		}
		return "mips"
	case 0x0A: // EM_MIPS_RS4_BE = 10 (老的 big-endian MIPS,少见) / EM_MIPS_RS4_BE = 10 (old big-endian MIPS, rare)
		if is64 {
			return "mips64"
		}
		return "mips"
	case 0xF3: // EM_RISCV = 243, 32 和 64 位都用这个值 / EM_RISCV = 243, both 32 and 64-bit use this value
		if is64 {
			return "riscv64"
		}
		return "riscv32"
	case 0x02: // EM_SPARC = 2 / EM_SPARC = 2
		if is64 {
			return "sparc64"
		}
		return "sparc"
	case 0x2B: // EM_SPARCV9 = 43 (其实这个是 Sparc v9 就是 64 位) / EM_SPARCV9 = 43 (actually this is Sparc v9 which is 64-bit)
		return "sparc64"
	case 0x14: // EM_PPC = 20 / EM_PPC = 20
		if is64 {
			return "ppc64"
		}
		return "ppc"
	case 0x15: // EM_PPC64 = 21 / EM_PPC64 = 21
		return "ppc64"
	case 0x16: // EM_S390 = 22 (IBM System/390) / EM_S390 = 22 (IBM System/390)
		if is64 {
			return "s390x"
		}
		return "s390"
	case 0x3C: // EM_S390 旧别名 = 60 / EM_S390 old alias = 60
		return "s390x"
	case 0x12: // EM_SPARC32PLUS = 18 (SPARC v8+) / EM_SPARC32PLUS = 18 (SPARC v8+)
		return "sparc"
	case 0x102: // EM_LOONGARCH = 258 (龙芯 LoongArch) / EM_LOONGARCH = 258 (Loongson LoongArch)
		if is64 {
			return "loongarch64"
		}
		return "loongarch32"
	default:
		return fmt.Sprintf("elf-machine-%d", m)
	}
}

// --------- PE (Windows) ---------

func peArchs(head []byte, size int64) ([]string, bool) {
	// 0x3C -> e_lfanew (DWORD): 指向 PE signature / 0x3C -> e_lfanew (DWORD): points to PE signature
	if len(head) < 0x40 {
		return nil, false
	}
	eLfanew := binary.LittleEndian.Uint32(head[0x3C:0x40])
	if size < 24 || eLfanew > uint32(size)-24 {
		return nil, false
	}
	if uint32(len(head)) < eLfanew+24 {
		// 头读的不够长,按读不到处理 / Header not long enough, treat as not readable
		return nil, false
	}
	// PE signature "PE\0\0" 4 bytes, 紧跟 COFF File Header: / PE signature "PE\0\0" 4 bytes, followed by COFF File Header:
	//   Machine           2 bytes /   Machine           2 字节
	//   NumberOfSections  2 bytes /   NumberOfSections  2 字节
	if !bytes.Equal(head[eLfanew:eLfanew+4], []byte("PE\x00\x00")) {
		return nil, false
	}
	machine := binary.LittleEndian.Uint16(head[eLfanew+4 : eLfanew+6])
	return []string{peMachineName(machine)}, true
}

func peMachineName(m uint16) string {
	switch m {
	case 0x014C:
		return "x86"
	case 0x8664:
		return "x86_64 (AMD64)"
	case 0xAA64:
		return "arm64"
	case 0x01C0:
		return "arm"
	case 0x01C4:
		return "armv7"
	case 0x0200:
		return "ia64"
	default:
		return fmt.Sprintf("pe-machine-0x%x", m)
	}
}

// --------- ar archive (.a 静态库) --------- / --------- ar archive (.a static library) ---------

// archiveArchs 遍历 ar 归档,对每个成员识别 ELF/Mach-O 再归并 / archiveArchs traverses the ar archive, identifies ELF/Mach-O for each member, then merges
// 返回 (成员格式集合, 架构集合),成员格式用于推断 .a 的平台 / Returns (member format set, architecture set); member format is used to infer the platform of .a
func archiveArchs(head []byte, size int64) ([]string, []string) {
	// ar format: / ar 格式:
	//   8 bytes magic: "!<arch>\n" /   8 字节魔数: "!<arch>\n"
	//   每个成员: 58 bytes header, 接着是成员数据(按 2 bytes 对齐) /   Each member: 58 bytes header, followed by member data (2-byte aligned)
	//   header 里前 16 bytes 是文件名,然后是 timestamp, uid, gid, mode, size(10 bytes, decimal ASCII with space pad), /   The first 16 bytes of the header are the filename, then timestamp, uid, gid, mode, size(10 bytes, decimal ASCII with space pad),
	//   最后 2 bytes 是 `\x60\n` /   The last 2 bytes are `\x60\n`
	archSet := map[string]struct{}{}
	formatSet := map[string]struct{}{}
	off := int64(8)
	end := size
	if int64(len(head)) < end {
		end = int64(len(head))
	}
	for off+60 <= end {
		hdr := head[off : off+60]
		// size 字段: hdr[48:58] 十进制 ASCII 空格填充 / size field: hdr[48:58] decimal ASCII space-padded
		sizeStr := strings.TrimSpace(string(hdr[48:58]))
		var memberSize int64
		fmt.Sscanf(sizeStr, "%d", &memberSize)
		// 末尾两个 magic bytes: hdr[58]=0x60, hdr[59]=0x0A / Last two magic bytes: hdr[58]=0x60, hdr[59]=0x0A
		if hdr[58] != 0x60 || hdr[59] != 0x0A {
			break
		}
		off += 60

		// BSD 长文件名格式: 成员名以 "#1/N" 开头,表示文件名跟在头后 N 字节 / BSD long filename format: member name starts with "#1/N", meaning the filename follows the header by N bytes
		// 需要跳过文件名才能到达成员数据 (目标文件) / Need to skip the filename to reach the member data (object file)
		// 参见: https://en.wikipedia.org/wiki/Ar_(Unix)#BSD_variant / See: https://en.wikipedia.org/wiki/Ar_(Unix)#BSD_variant
		nameField := strings.TrimSpace(string(hdr[:16]))
		var nameSkip int64
		if strings.HasPrefix(nameField, "#1/") {
			var n int64
			fmt.Sscanf(nameField[3:], "%d", &n)
			nameSkip = n
			if off+nameSkip > end {
				break
			}
			// memberSize 包含文件名长度,实际成员数据大小 = memberSize - nameSkip / memberSize includes the filename length, actual member data size = memberSize - nameSkip
			memberSize -= nameSkip
			off += nameSkip
		}

		if off+memberSize > end {
			break
		}
		if memberSize >= 4 {
			// 给每个成员读 64 字节: ELF e_machine 在 0x12 (18), / Read 64 bytes for each member: ELF e_machine is at 0x12 (18),
			// Mach-O cputype 在 4:8, PE signature+machine 需要更多 / Mach-O cputype is at 4:8, PE signature+machine needs more
			memberWant := min64(64, memberSize)
			if int64(len(head))-off < memberWant {
				memberWant = int64(len(head)) - off
			}
			if memberWant >= 4 {
				memberHead := head[off : off+memberWant]
				// 递归做轻量识别 / Recursively do lightweight identification
				fmt0, archs0 := detectBinaryArch(memberHead, memberSize)
				if fmt0 != "Unknown" && fmt0 != "Archive(.a)" {
					formatSet[fmt0] = struct{}{}
				}
				for _, a := range archs0 {
					if a != "" {
						archSet[a] = struct{}{}
					}
				}
			}
		}
		// 成员按 2 字节对齐 / Members are 2-byte aligned
		if memberSize%2 == 1 {
			memberSize++
		}
		off += memberSize
		if off > end {
			break
		}
	}
	formats := make([]string, 0, len(formatSet))
	for f := range formatSet {
		formats = append(formats, f)
	}
	sort.Strings(formats)
	out := make([]string, 0, len(archSet))
	for k := range archSet {
		out = append(out, k)
	}
	sort.Strings(out)
	return formats, out
}
