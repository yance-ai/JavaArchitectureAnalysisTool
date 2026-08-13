package main

import (
	"fmt"
	"os"
	"strings"
)

// lang 当前语言,默认 zh / Current language, default zh
var lang = "zh"

// SetLang 设置当前语言 (zh/en),返回实际设置的语言 / Set current language (zh/en), returns the actually set language
func SetLang(l string) string {
	l = strings.ToLower(strings.TrimSpace(l))
	switch l {
	case "en", "en-us", "en-gb", "english":
		lang = "en"
	case "zh", "zh-cn", "zh-tw", "chinese":
		lang = "zh"
	default:
		lang = detectLang()
	}
	return lang
}

// GetLang 获取当前语言 / Get current language
func GetLang() string {
	return lang
}

// detectLang 从系统环境变量检测语言,默认返回 zh / Detect language from system env vars, defaults to zh
func detectLang() string {
	for _, env := range []string{"LANG", "LC_ALL", "LC_MESSAGES", "LC_CTYPE"} {
		v := os.Getenv(env)
		lower := strings.ToLower(v)
		if strings.HasPrefix(lower, "zh") {
			return "zh"
		}
		if strings.HasPrefix(lower, "en") {
			return "en"
		}
	}
	return "zh"
}

// T 翻译简单消息,key 对应翻译表 / Translate a message by key from the translation table
func T(key string, args ...interface{}) string {
	if lang == "en" {
		if s, ok := enStrings[key]; ok {
			if len(args) > 0 {
				return fmt.Sprintf(s, args...)
			}
			return s
		}
	}
	// 默认中文 / Default Chinese
	if s, ok := zhStrings[key]; ok {
		if len(args) > 0 {
			return fmt.Sprintf(s, args...)
		}
		return s
	}
	// key 未找到,原样返回 / Key not found, return as-is
	if len(args) > 0 {
		return fmt.Sprintf(key, args...)
	}
	return key
}

// formatDesc 根据当前语言返回二进制格式的描述 / Return binary format description based on current language
func formatDesc(format string) string {
	if lang == "en" {
		switch format {
		case "ELF":
			return "ELF (Linux/BSD executable)"
		case "Mach-O":
			return "Mach-O (macOS/iOS executable)"
		case "PE":
			return "PE (Windows executable)"
		case "Archive(.a)":
			return "Archive(.a) (Unix static library)"
		case "XCOFF":
			return "XCOFF (AIX executable)"
		default:
			return format + " (unknown format)"
		}
	}
	// 默认中文 / Default Chinese
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

// archDesc 根据当前语言返回 CPU 架构的描述 / Return CPU architecture description based on current language
func archDesc(arch string) string {
	if lang == "en" {
		switch arch {
		case "i386":
			return "i386 (Intel 32-bit)"
		case "x86":
			return "x86 (Intel 32-bit)"
		case "x86_64":
			return "x86_64 (Intel 64-bit)"
		case "x86_64 (AMD64)":
			return "x86_64 (AMD64, Intel 64-bit)"
		case "arm":
			return "arm (ARM 32-bit)"
		case "armv7":
			return "armv7 (ARM v7 32-bit)"
		case "aarch64":
			return "aarch64 (ARM 64-bit)"
		case "arm64":
			return "arm64 (ARM 64-bit)"
		case "arm64_ilp32":
			return "arm64_ilp32 (ARM 64-bit ILP32)"
		case "mips":
			return "mips (MIPS 32-bit)"
		case "mips64":
			return "mips64 (MIPS 64-bit)"
		case "riscv32":
			return "riscv32 (RISC-V 32-bit)"
		case "riscv64":
			return "riscv64 (RISC-V 64-bit)"
		case "sparc":
			return "sparc (SPARC 32-bit)"
		case "sparc64":
			return "sparc64 (SPARC 64-bit)"
		case "ppc":
			return "ppc (PowerPC 32-bit)"
		case "ppc64":
			return "ppc64 (PowerPC 64-bit)"
		case "s390x":
			return "s390x (IBM System/390 64-bit)"
		case "s390":
			return "s390 (IBM System/390 32-bit)"
		case "ia64":
			return "ia64 (Intel Itanium 64-bit)"
		case "loongarch32":
			return "loongarch32 (LoongArch 32-bit)"
		case "loongarch64":
			return "loongarch64 (LoongArch 64-bit)"
		default:
			return arch
		}
	}
	// 默认中文 / Default Chinese
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

// archTagDesc 根据当前语言将架构列表拼接为带描述的标签 / Join architecture list into a descriptive tag based on current language
func archTagDesc(archs []string) string {
	if len(archs) == 0 {
		return "?"
	}
	parts := make([]string, 0, len(archs))
	for _, a := range archs {
		parts = append(parts, archDesc(a))
	}
	return strings.Join(parts, " + ")
}

// statusName 根据当前语言返回状态名的翻译 / Return translated status name based on current language
func statusName(status string) string {
	if lang == "en" {
		switch status {
		case "本地指定":
			return "local"
		case "已有":
			return "exists"
		case "需下载":
			return "need_download"
		case "缺少来源":
			return "missing_source"
		case "已支持":
			return "supported"
		default:
			return status
		}
	}
	return status
}

// zhStrings 中文翻译表 / Chinese translation table
var zhStrings = map[string]string{
	// 通用 / General
	"unknown_cmd":        "未知子命令: %s",
	"jar_missing":        "缺少 jar 文件路径或目录路径",
	"pom_missing":        "缺少 pom.xml 文件路径",
	"overlay_missing":    "缺少 jar 文件路径",
	"open_failed":        "打开 %s 失败: %v",
	"stat_failed":        "访问 %s 失败: %v",
	"parse_failed":       "解析 %s 失败: %v",
	"walk_failed":        "遍历目录 %s 失败: %v",
	"no_jar_found":       "目录 %s 下未找到任何 .jar 文件",
	"create_outdir_fail": "创建 outdir %s 失败: %v",

	// 进度 / Progress
	"scan_dir":       "扫描目录: %s\n找到 %d 个 jar 文件,开始逐个解析...",
	"scan_complete":  "完成: 成功解析 %d/%d 个 jar,其中 %d 个含 C/C++ 本地产物",
	"dir_scan_title": "目录扫描: %s (%d 个 jar)",

	// jar 分析结果 / Jar analysis results
	"cclib_header":      "【C/C++ 本地架构产物】 共 %d 个文件:",
	"cclib_no_native":   "【C/C++ 本地架构产物】未发现 (纯 Java jar)",
	"platforms":         "平台: %v",
	"archs":             "架构: %v",
	"overview":          "--- 各平台支持架构总览 ---",
	"gap_analysis":      "--- 架构缺失分析 (相对于同平台其他库的完整架构集) ---",
	"gap_missing":       "- %s: 支持 [%s]  缺失 [%s] ⚠",
	"gap_total":         "总计: 共发现 %d 个架构缺失问题",
	"gap_complete":      "✓ 架构完整: 所有本地库在各平台上均支持相同的架构集",
	"gap_coverage":      "各平台架构覆盖情况:",
	"gap_coverage_item": "  %s: %d 个架构 [%s]",

	// 库列表 / Library list
	"libs_header":   "解析到 %d 个库 (分布在 %d 个 jar 文件中):",
	"libs_unknown":  "[未知来源] 下的 %d 个库:",
	"libs_jar":      "[%s] 该 jar 下的 %d 个依赖库:",
	"libs_indirect": " (间接)",
	"deps_header":   "依赖关系 (%d 条):",

	// overlay
	"overlay_header":        "=== overlay: %s ===",
	"target_platform":       "目标平台: %s / %s",
	"output_dir":            "输出目录: %s",
	"no_native":             "✓ 该 jar 内不包含任何 C/C++ 本地库,无需做 overlay 处理。",
	"overlay_plan":          "--- 覆盖计划 ---",
	"total_libs":            "jar 内本地库总数: %d 个 (归一化后)",
	"supported_arch":        "目标平台 %s 已支持 %s 架构: %d 个  ✓",
	"missing_arch":          "目标平台 %s 缺少 %s 架构: %d 个  ⚠  ← 需要覆盖",
	"other_platform":        "仅存在于其他平台 (非 %s): %d 个 (无需覆盖)",
	"mirror_default":        "镜像源: 未指定 -mirror,使用 Maven 仓库默认源 (%d 个)",
	"mirror_specified":      "镜像源: %s",
	"already_supported":     "--- 已支持目标架构,无需覆盖 ---",
	"tag_local":             "✓ 使用本地文件",
	"tag_exist":             "✓ 输出目录已存在",
	"tag_download":          "⤓ 需下载",
	"tag_missing":           "✗ 缺少来源 (需指定 -local 或 -mirror)",
	"tag_supported":         "支持",
	"none":                  "无",
	"size_hint":             "  (本地 %d B vs jar 内 %d B,差异>2×,请确认版本)",
	"target_arch":           "目标架构: %s  jar 内已支持: %s  缺失: [%s]",
	"output_path":           "输出:    %s",
	"jar_sample":            "jar 样本: %s  (jar 内大小: %d B)",
	"maven_info":            "Maven:   %s:%s:%s",
	"source_jar":            "来源jar: %s",
	"local_source":          "本地源:  %s  (大小: %d B)%s",
	"local_arch":            "本地架构: %s",
	"candidate_sources":     "候选源 (%d 个):",
	"download_url":          "URL:     %s",
	"statistics":            "--- 统计 ---",
	"stat_total":            "jar 内本地库总数: %d (归一化后)",
	"stat_supported":        "目标平台 %s 已支持 %s: %d 个  ✓",
	"stat_missing":          "目标平台 %s 缺少 %s: %d 个  ⚠",
	"stat_other":            "仅存在于其他平台 (非 %s): %d 个",
	"stat_dist":             "状态分布: %s",
	"downloading":           "下载 %s → %s",
	"try_source":            "尝试源 %d: %s",
	"download_success":      "✓ 成功 (%d B)  %s",
	"download_fail":         "✗ 失败: %v",
	"all_sources_fail":      "✗ 所有源均失败: %v",
	"copy_fail":             "✗ 复制失败 %s: %v",
	"need_download":         "⚠  需要下载 %d 个文件,加 -download 开关后实际下载,或手动复制到: %s",
	"java_cmd":              "java -Djava.library.path=%s -jar %s",
	"java_cmd_hint":         "原理说明: JVM 加载本地库时先搜索 java.library.path,\n找到同名文件后不再从 jar 包内部提取,实现外部库优先覆盖。",
	"process_fail":          "✗ 处理失败 %d 个,请检查上方日志。",
	"link_symlink":          "  → 软链接 %s → %s",
	"link_hardlink":         "  → 硬链接 %s → %s (软链接不可用)",
	"link_copy":             "  → 复制 %s → %s (软链接/硬链接不可用)",
	"link_fail":             "  ✗ 兼容链接失败 %s: %v",
	"link_skip":             "  → 跳过 %s (与目标同名)",
	"link_arch_replace":     "  → 架构替换 %s → %s (原 %s → 目标 %s)",
	"cross_platform_notice": "⚠ 跨平台部署: 目标 %s ≠ 当前 %s,兼容链接将使用文件复制 (确保目标系统可移植)",

	// 下载相关 / Download related
	"cannot_read":        "(无法读取)",
	"cannot_read_header": "(无法读取文件头)",
	"format_arch":        "格式=%s  架构=未知",
	"format_arch_list":   "格式=%s  架构=[%s]",
}

// enStrings 英文翻译表 / English translation table
var enStrings = map[string]string{
	// General
	"unknown_cmd":        "Unknown subcommand: %s",
	"jar_missing":        "Missing jar file path or directory path",
	"pom_missing":        "Missing pom.xml file path",
	"overlay_missing":    "Missing jar file path",
	"open_failed":        "Failed to open %s: %v",
	"stat_failed":        "Failed to access %s: %v",
	"parse_failed":       "Failed to parse %s: %v",
	"walk_failed":        "Failed to walk directory %s: %v",
	"no_jar_found":       "No .jar files found in directory %s",
	"create_outdir_fail": "Failed to create outdir %s: %v",

	// Progress
	"scan_dir":       "Scanning directory: %s\nFound %d jar files, parsing...",
	"scan_complete":  "Done: Successfully parsed %d/%d jars, %d contain C/C++ native artifacts",
	"dir_scan_title": "Directory scan: %s (%d jars)",

	// Jar analysis results
	"cclib_header":      "[C/C++ Native Artifacts] %d files total:",
	"cclib_no_native":   "[C/C++ Native Artifacts] None found (pure Java jar)",
	"platforms":         "Platforms: %v",
	"archs":             "Architectures: %v",
	"overview":          "--- Architecture Support by Platform ---",
	"gap_analysis":      "--- Architecture Gap Analysis (relative to complete set of other libraries on same platform) ---",
	"gap_missing":       "- %s: supports [%s]  missing [%s] ⚠",
	"gap_total":         "Total: %d architecture gap issue(s) found",
	"gap_complete":      "✓ Architecture complete: All native libraries support the same architecture set on each platform",
	"gap_coverage":      "Architecture coverage by platform:",
	"gap_coverage_item": "  %s: %d architecture(s) [%s]",

	// Library list
	"libs_header":   "Parsed %d libraries (in %d jar files):",
	"libs_unknown":  "%d libraries from [unknown source]:",
	"libs_jar":      "%d dependencies from [%s]:",
	"libs_indirect": " (indirect)",
	"deps_header":   "Dependencies (%d relations):",

	// Overlay
	"overlay_header":        "=== overlay: %s ===",
	"target_platform":       "Target platform: %s / %s",
	"output_dir":            "Output directory: %s",
	"no_native":             "✓ This jar contains no C/C++ native libraries, no overlay needed.",
	"overlay_plan":          "--- Overlay Plan ---",
	"total_libs":            "Total native libs in jar: %d (normalized)",
	"supported_arch":        "Target platform %s already supports %s: %d  ✓",
	"missing_arch":          "Target platform %s missing %s: %d  ⚠  ← needs overlay",
	"other_platform":        "Only exists on other platforms (not %s): %d (no overlay needed)",
	"mirror_default":        "Mirror: No -mirror specified, using Maven default sources (%d)",
	"mirror_specified":      "Mirror: %s",
	"already_supported":     "--- Already supported target architecture, no overlay needed ---",
	"tag_local":             "✓ Using local file",
	"tag_exist":             "✓ Already exists in output directory",
	"tag_download":          "⤓ Need download",
	"tag_missing":           "✗ Missing source (specify -local or -mirror)",
	"tag_supported":         "supports",
	"none":                  "none",
	"size_hint":             "  (local %d B vs jar %d B, diff >2×, please verify version)",
	"target_arch":           "Target arch: %s  in-jar supports: %s  missing: [%s]",
	"output_path":           "Output:    %s",
	"jar_sample":            "Jar sample: %s  (in-jar size: %d B)",
	"maven_info":            "Maven:   %s:%s:%s",
	"source_jar":            "Source jar: %s",
	"local_source":          "Local:  %s  (size: %d B)%s",
	"local_arch":            "Local arch: %s",
	"candidate_sources":     "Candidate sources (%d):",
	"download_url":          "URL:     %s",
	"statistics":            "--- Statistics ---",
	"stat_total":            "Total native libs in jar: %d (normalized)",
	"stat_supported":        "Target platform %s supports %s: %d  ✓",
	"stat_missing":          "Target platform %s missing %s: %d  ⚠",
	"stat_other":            "Only on other platforms (not %s): %d",
	"stat_dist":             "Status distribution: %s",
	"downloading":           "Downloading %s → %s",
	"try_source":            "Trying source %d: %s",
	"download_success":      "✓ Success (%d B)  %s",
	"download_fail":         "✗ Failed: %v",
	"all_sources_fail":      "✗ All sources failed: %v",
	"copy_fail":             "✗ Copy failed %s: %v",
	"need_download":         "⚠  Need to download %d file(s), add -download flag to actually download, or copy manually to: %s",
	"java_cmd":              "java -Djava.library.path=%s -jar %s",
	"java_cmd_hint":         "Tip: JVM searches java.library.path first for native libraries.\nOnce found, it won't extract from jar, enabling external library override.",
	"process_fail":          "✗ %d processing failed, please check the logs above.",
	"link_symlink":          "  → Symlink %s → %s",
	"link_hardlink":         "  → Hardlink %s → %s (symlink unavailable)",
	"link_copy":             "  → Copy %s → %s (symlink/hardlink unavailable)",
	"link_fail":             "  ✗ Compat link failed %s: %v",
	"link_skip":             "  → Skip %s (same as target)",
	"link_arch_replace":     "  → Arch replace %s → %s (from %s → target %s)",
	"cross_platform_notice": "⚠ Cross-platform deployment: target %s ≠ current %s, compat links will use file copy (portable to target system)",

	// Download related
	"cannot_read":        "(unreadable)",
	"cannot_read_header": "(cannot read file header)",
	"format_arch":        "format=%s  arch=unknown",
	"format_arch_list":   "format=%s  arch=[%s]",
}
