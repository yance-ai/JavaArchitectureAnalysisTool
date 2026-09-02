# JavaArchitectureAnalysisTool

一个用于分析 Java jar 包内部结构的命令行工具,重点识别 jar 内嵌的 C/C++ 本地库(.so / .dylib / .dll / .a / .jnilib / .lib)所支持的平台和 CPU 架构,帮助判断 jar 是否能在目标平台(如 ARM Linux、Apple Silicon macOS)运行。

## 功能概览

- **`jar` 子命令**:扫描 jar 内的本地二进制产物,识别格式(ELF / Mach-O / PE / XCOFF / Archive)和 CPU 架构(x86_64 / aarch64 / riscv64 / loongarch64 / s390x / ppc64 等),并按平台归一化分析架构覆盖差异
- **`pom` 子命令**:解析 Maven 的 pom.xml,输出完整传递依赖树和依赖关系图
- **`overlay` 子命令**:生成本地库覆盖方案,基于 `java.library.path` 原理实现外部库优先加载,跳过 jar 内同名库(用于补架构、换版本、修复漏洞等场景)

## 支持的 jar 打包格式

| 打包格式 | 典型后缀 | 是否支持 |
|---------|---------|:---:|
| maven-assembly `with-dependencies`(平铺式) | `.jar` | ✅ |
| Spring Boot Executable jar(嵌套式 `BOOT-INF/lib/*.jar`) | `.jar` | ✅ |
| WAR 包(`WEB-INF/lib/*.jar`) | `.war` | ✅ |
| EAR 包(`lib/*.jar`) | `.ear` | ✅ |
| Hadoop/Spark tar 分发解压后的 lib 目录 | 目录 | ✅ |
| Maven 本地仓库目录 | 目录 | ✅ |

`jar` 子命令传目录时会递归扫描所有 `.jar` 文件,合并结果;对每个 jar 内部的嵌套 jar 也会递归扫描(最大嵌套深度 5 层,单嵌套 jar 限 200MB,防 zip 炸弹)。

## 安装

直接使用预编译二进制(见 `dist/` 目录),或自行构建:

```bash
go build -trimpath -ldflags "-s -w" -o JavaArchitectureAnalysisTool .
```

或使用 `build.sh` 脚本一键编译所有平台:

```bash
./build.sh              # 编译所有平台到 dist/
./build.sh current      # 仅编译当前平台
./build.sh linux        # 仅编译 Linux (amd64 + arm64)
./build.sh windows      # 仅编译 Windows (amd64)
./build.sh darwin       # 仅编译 macOS (含 universal)
./build.sh clean        # 清理 dist/
```

跨平台手动编译:

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
# macOS Universal Binary (需在 macOS 上执行)
lipo -create -output JavaArchitectureAnalysisTool-darwin-universal \
    JavaArchitectureAnalysisTool-darwin-amd64 \
    JavaArchitectureAnalysisTool-darwin-arm64
```

目标机器不需要安装 Go 环境,二进制为静态链接。

## 使用守则

### 1. `jar` 子命令 — 分析本地架构产物

```bash
# 单个 jar
JavaArchitectureAnalysisTool jar /path/to/app.jar

# 目录下所有 jar (Hadoop lib / Maven 仓库等)
JavaArchitectureAnalysisTool jar /opt/hadoop/share/hadoop/common/lib/

# 离线模式,不访问 Maven Central (架构扫描本身不联网,仅库识别离线)
JavaArchitectureAnalysisTool jar -offline /path/to/app.jar

# 英文输出
JavaArchitectureAnalysisTool jar -lang en /path/to/app.jar

# 参数可混排 (位置参数前后均可)
JavaArchitectureAnalysisTool jar /path/to/app.jar -offline -lang en
```

**参数说明**:

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-offline` | `false` | 离线模式,跳过 Maven Central 查询,仅靠 jar 内嵌元数据识别库 |
| `-lang` | 自动检测 | 输出语言:`zh` / `en`(自动读取系统 `LANG` 环境变量) |

**输出内容**:

- **C/C++ 本地架构产物列表**:逐个列出 jar 内的本地库文件,标注格式(中文)、架构(中文)、文件大小、来源路径
- **各平台支持架构总览**:按平台(Linux / macOS / Windows / AIX)列出支持的架构集合
- **架构缺失分析**:相对于同平台其他库的完整架构集,指出某个库缺失哪些架构(用归一化库名合并同库不同架构的文件,如 `libsnappyjava.dylib` + `libsnappyjava.jnilib` 会合并)
- **依赖库列表**:按 jar 文件路径分组打印,标题只打印一次,避免重复

**架构识别能力**:

| 格式 | 支持的架构 |
|------|-----------|
| ELF (Linux/BSD) | x86_64、i386、aarch64、arm、armv7、riscv64、riscv32、loongarch64、loongarch32、mips、mips64、ppc、ppc64、s390、s390x、sparc、sparc64、ia64 |
| Mach-O (macOS/iOS) | x86_64、i386、arm64、armv7;支持 Fat/Universal Binary(一个文件含多 slice,会去重) |
| PE (Windows) | x86_64 (AMD64)、x86 (i386)、ia64 |
| XCOFF (AIX) | ppc、ppc64 |
| Archive (.a / .lib) | 递归解析内部成员,支持 GNU ar 和 BSD ar 格式,按内部成员的格式(ELF/Mach-O)推断架构 |

### 2. `pom` 子命令 — 解析 Maven 依赖树

```bash
# 离线模式 (默认),只用本地 ~/.m2/repository
JavaArchitectureAnalysisTool pom pom.xml

# 允许访问 Maven Central 拉取缺失的传递依赖 pom
JavaArchitectureAnalysisTool pom -offline=false pom.xml

# 指定私有仓库
JavaArchitectureAnalysisTool pom -remote=https://my.repo/maven2/ pom.xml

# 英文输出
JavaArchitectureAnalysisTool pom -lang en pom.xml
```

**参数说明**:

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-offline` | `true` | 是否只使用本地 `~/.m2/repository`,不访问远程 Maven Central |
| `-remote` | — | 远程仓库 URL(仅当 `-offline=false` 时生效,默认 Maven Central) |
| `-lang` | 自动检测 | 输出语言:`zh` / `en`(自动读取系统 `LANG` 环境变量) |

输出完整的传递依赖列表和 `ID → DependsOn` 依赖关系图。

### 3. `overlay` 子命令 — 本地库覆盖方案

**原理**:JVM 加载本地库时先搜索 `-Djava.library.path` 指定的目录,找到同名文件后不再从 jar 包内部提取。把所需本地库放到外部目录,就能跳过 jar 内部的同名库,实现补架构、换版本、修复漏洞等目的,对 jar 本身完全无侵入。

```bash
# 基本用法:只分析,打印建议和下载 URL
JavaArchitectureAnalysisTool overlay /path/to/app.jar

# 指定目标平台/架构
JavaArchitectureAnalysisTool overlay app.jar -os linux -arch aarch64

# 指定 macOS ARM (Apple Silicon) 目标
JavaArchitectureAnalysisTool overlay app.jar -os darwin -arch arm64

# 指定 Windows x86_64 目标
JavaArchitectureAnalysisTool overlay app.jar -os windows -arch x86_64

# 默认下载:不指定 -mirror,自动从 Maven 仓库下载 jar 并提取 .so
JavaArchitectureAnalysisTool overlay app.jar -os linux -arch aarch64 -download

# 指定本地已有的库 + 镜像 URL 模板 + 实际下载
JavaArchitectureAnalysisTool overlay app.jar \
    -local libsnappyjava.so=/opt/libs/libsnappyjava.so \
    -mirror https://mirrors.example.com/native/{lib}/{os}/{arch}/{libfile} \
    -download -outdir /opt/app-native-libs

# 指定多个本地库 + 设置下载超时
JavaArchitectureAnalysisTool overlay app.jar \
    -local libsnappyjava.so=/opt/libs/libsnappyjava.so \
    -local libzstd-jni.so=/opt/libs/libzstd-jni.so \
    -download -timeout 120 -outdir /opt/app-native-libs

# 英文输出
JavaArchitectureAnalysisTool overlay app.jar -lang en -os linux -arch aarch64 -download

# 参数可混排 (位置参数前后均可)
JavaArchitectureAnalysisTool overlay -os linux -arch aarch64 app.jar -download
```

**参数说明**:

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-os` | 当前系统 | 目标 OS:`linux` / `darwin` / `windows` / `aix` |
| `-arch` | 当前架构 | 目标架构:`x86_64` / `aarch64` / `arm64` / `arm` / `riscv64` 等 |
| `-outdir` | `./native-overlay` | 外部库输出目录 |
| `-local` | — | 指定某个库的本地文件,格式 `libname=path`,可重复传 |
| `-mirror` | — | 镜像 URL 模板,占位符:`{lib}` `{libfile}` `{os}` `{arch}` |
| `-download` | `false` | 实际下载缺失的库(默认只打印 URL) |
| `-timeout` | `60` | 下载超时秒数 |
| `-lang` | 自动检测 | 输出语言:`zh` / `en`(自动读取系统 `LANG` 环境变量) |

**本地库来源优先级**:

1. `-local` 指定的本地文件 → 复制到 outdir(会与 jar 内同名文件比大小,差异 >2× 会告警)
2. outdir 里已有的同名文件 → 跳过
3. 指定了 `-mirror` → 使用用户指定的镜像模板生成 `.so` 直接下载 URL;加 `-download` 后实际下载
4. 未指定 `-mirror` → 自动从嵌套 jar 的 `pom.properties` 提取 Maven 坐标,从 Maven 仓库下载对应架构的 jar 包,再从中提取 `.so` 文件

**Maven 仓库下载流程**(未指定 `-mirror` 时自动执行):

1. 扫描 jar 时读取每个嵌套 jar 的 `META-INF/maven/*/pom.properties`,提取 `groupId:artifactId:version`
2. 从原 jar 文件名提取 classifier(如 `netty-transport-native-epoll-4.1.128.Final-linux-x86_64.jar` → `linux-x86_64`)
3. 将 classifier 中的架构关键词替换为目标架构,生成多个候选(兼容不同命名约定):
   - `x86_64` → `aarch_64`(netty 约定) / `aarch64`(通用) / `arm64`(Apple 约定)
4. 对每个候选 classifier × 每个镜像源构造 jar 下载 URL,依次尝试
5. 下载 jar 后打开 zip,遍历条目找到匹配目标架构的 `.so` 文件,提取到 outdir

**Maven 镜像源列表**(按优先级排序,国内优先):

| 序号 | 镜像源 | Base URL |
|:---:|--------|----------|
| 1 | 阿里云 | `https://maven.aliyun.com/repository/central` |
| 2 | 华为云 | `https://repo.huaweicloud.com/repository/maven-central` |
| 3 | 腾讯云 | `https://mirrors.cloud.tencent.com/nexus/repository/maven-public` |
| 4 | Maven Central | `https://repo1.maven.org/maven2` |
| 5 | Maven Central (备用) | `https://repo.maven.apache.org/maven2` |

下载 URL 格式: `{base}/{groupIdPath}/{artifactId}/{version}/{artifactId}-{version}-{classifier}.jar`

**URL 模板占位符**:

| 占位符 | 含义 | 示例 |
|--------|------|------|
| `{lib}` | 库根名(去版本号、去后缀) | `libsnappyjava` |
| `{libfile}` | 实际文件名 | `libsnappyjava.so` |
| `{os}` | 目标 OS | `linux` |
| `{arch}` | 目标架构 | `aarch64` |

示例模板:`https://mirrors.example.com/native/{lib}/{os}/{arch}/{libfile}`

**输出尾部会给出 Java 启动参数建议**:

```
java -Djava.library.path=/opt/app-native-libs -jar /path/to/app.jar
```

## 输出规范

- **格式名带中文说明**:`ELF (Linux/BSD 可执行文件)`、`Mach-O (macOS/iOS 可执行文件)`、`PE (Windows 可执行文件)`、`XCOFF (AIX 可执行文件)`、`Archive(.a) (Unix 静态库)`
- **架构名带中文说明**(详细列表):`x86_64 (Intel 64位)`、`aarch64 (ARM 64位)`、`riscv64 (RISC-V 64位)`、`loongarch64 (龙芯 64位)` 等
- **概览/统计区用简写**:`[i386、x86_64]`,避免长中文让输出变乱
- **详细文件列表用完整中文**:`arch=x86_64 (Intel 64位) + arm64 (ARM 64位)`,保证可读性
- **进度信息走 stderr,结果走 stdout**:支持 `> result.txt` 把纯净结果重定向到文件
- **路径脱敏**:输出中的用户主目录自动替换为 `~`,隐藏电脑账号等信息

## 国际化 (i18n)

工具支持中文和英文输出,默认从系统 `LANG` 环境变量自动检测语言(检测失败时默认中文):

```bash
# 自动检测 (默认)
JavaArchitectureAnalysisTool jar app.jar

# 强制英文
JavaArchitectureAnalysisTool jar app.jar -lang en

# 强制中文
JavaArchitectureAnalysisTool jar app.jar -lang zh

# 通过环境变量指定
LANG=en_US.UTF-8 JavaArchitectureAnalysisTool jar app.jar
```

所有子命令(`pom`、`jar`、`overlay`)均支持 `-lang` 参数。

## 归一化规则

为避免同一库因文件名差异(扩展名、架构词、平台词)被误判为不同库,`normalizeLibraryName` 会:

1. **统一扩展名**:`.jnilib` → `.dylib`(都是 macOS 动态库)
2. **去掉架构关键词**:`aarch_64` / `aarch64` / `aarch_` / `x86_64` / `x86_` / `x86` / `arm64` / `amd64` / `riscv64` / `loongarch64` / `sparc64` / `ppc64` / `s390x` / `mips64` / `i386` / `i686` / `_64` / `_32` / `64` / `32` 等
3. **去掉平台关键词**:`linux` / `windows` / `win32` / `win64` / `win` / `macosx` / `darwin` / `osx` / `mac` / `sunos` / `aix`
4. **清理多余分隔符**:连续 `_` 合并,首尾 `_-.` 裁剪

示例:
- `libsnappyjava.dylib` + `libsnappyjava.jnilib` → `libsnappyjava.dylib`
- `netty_tcnative_osx_.jnilib` + `netty_tcnative_osx_aarch_.jnilib` → `netty_tcnative.dylib`
- `jline32.dll` + `jline64.dll` → `jline.dll`

## 跨平台支持矩阵

| 平台 | 架构 | 预编译二进制 |
|------|------|-------------|
| Linux | x86_64 | `JavaArchitectureAnalysisTool-linux-amd64` |
| Linux | aarch64 (ARM) | `JavaArchitectureAnalysisTool-linux-arm64` |
| Windows | x86_64 | `JavaArchitectureAnalysisTool-windows-amd64.exe` |
| macOS | x86_64 (Intel) | `JavaArchitectureAnalysisTool-darwin-amd64` |
| macOS | arm64 (Apple Silicon) | `JavaArchitectureAnalysisTool-darwin-arm64` |
| macOS | Universal | `JavaArchitectureAnalysisTool-darwin-universal` |

所有 Linux 二进制为静态链接,目标机器无需安装额外运行时。

## 注意事项

1. **`jar -offline` 仅影响库识别**:架构扫描本身不联网,`-offline=true` 只是让 `go-dep-parser` 不去 Maven Central 查 jar 的 GAV 坐标
2. **overlay 不修改原 jar**:所有外部库放到独立目录,通过 `-Djava.library.path` 指定,对原 jar 完全无侵入
3. **`-local` 指定的本地文件会做大小校验**:与 jar 内同名文件大小差异超过 2 倍会告警,提示确认版本
4. **下载使用原子写**:先写 `.part` 临时文件,完成后 rename,避免 HTTP 中断导致半截文件污染输出目录
5. **嵌套 jar 递归有保护**:最大深度 5 层、单嵌套 jar 限 200MB,防止 zip 炸弹
6. **参数混排支持**:所有子命令都支持 `app.jar -flag` 和 `-flag app.jar` 混排(手动重排了 Go flag 的位置参数限制)
7. **Maven 下载是下载 jar 再提取**:未指定 `-mirror` 时,工具会从 Maven 仓库下载对应架构的 jar 包,再从 jar 内提取 `.so` 文件(Maven 仓库不直接存储 `.so`)
8. **路径脱敏**:输出中的用户主目录自动替换为 `~`,隐藏电脑账号等敏感信息
9. **下载文件会做架构校验**:下载成功后会扫描文件头,确认格式和架构与目标匹配
