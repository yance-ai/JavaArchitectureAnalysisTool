#!/usr/bin/env bash
# build.sh — 跨平台编译 JavaArchitectureAnalysisTool / Cross-platform build
# 用法 / Usage:
#   ./build.sh              编译所有平台到 dist/                  Build all platforms to dist/
#   ./build.sh current      仅编译当前平台                        Build current platform only
#   ./build.sh linux        仅编译 Linux (amd64 + arm64)          Build Linux only
#   ./build.sh windows      仅编译 Windows (amd64)                Build Windows only
#   ./build.sh darwin       仅编译 macOS (amd64 + arm64 + universal)  Build macOS only
#   ./build.sh clean        清理 dist/ 目录                       Clean dist/ directory

set -euo pipefail

PROJECT="JavaArchitectureAnalysisTool"
DIST_DIR="dist"

# 颜色输出 / Colored output
red()    { printf "\033[31m%s\033[0m\n" "$*"; }
green()  { printf "\033[32m%s\033[0m\n" "$*"; }
yellow() { printf "\033[33m%s\033[0m\n" "$*"; }
blue()   { printf "\033[34m%s\033[0m\n" "$*"; }

# 双语输出 / Bilingual output
bi() { printf "%s / %s\n" "$1" "$2"; }
bi_blue()   { printf "\033[34m%s / %s\033[0m\n" "$1" "$2"; }
bi_green()  { printf "\033[32m%s / %s\033[0m\n" "$1" "$2"; }
bi_yellow() { printf "\033[33m%s / %s\033[0m\n" "$1" "$2"; }
bi_red()    { printf "\033[31m%s / %s\033[0m\n" "$1" "$2"; }

# 编译单个目标 / Build single target
build_one() {
    local goos=$1
    local goarch=$2
    local suffix=$3
    local output="${DIST_DIR}/${PROJECT}-${suffix}"

    printf "  -> %s/%s → %s ... " "$goos" "$goarch" "$output"
    GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags "-s -w" -o "$output" . && green "OK" || { bi_red "失败" "FAIL"; exit 1; }
}

# 编译 macOS Universal Binary / Build macOS Universal Binary
build_universal() {
    local amd64="${DIST_DIR}/${PROJECT}-darwin-amd64"
    local arm64="${DIST_DIR}/${PROJECT}-darwin-arm64"
    local output="${DIST_DIR}/${PROJECT}-darwin-universal"

    if [[ ! -f "$amd64" || ! -f "$arm64" ]]; then
        bi_yellow "  -> 跳过 universal (需要先编译 amd64 和 arm64)" "Skip universal (need amd64 and arm64 first)"
        return
    fi
    if [[ "$(uname -s)" != "Darwin" ]]; then
        bi_yellow "  -> 跳过 universal (需要在 macOS 上执行 lipo)" "Skip universal (lipo requires macOS)"
        return
    fi
    printf "  -> universal → %s ... " "$output"
    lipo -create -output "$output" "$amd64" "$arm64" && green "OK" || { bi_red "失败" "FAIL"; exit 1; }
}

# 编译所有平台 / Build all platforms
build_all() {
    bi_blue "=== 编译所有平台 ===" "=== Build All Platforms ==="
    mkdir -p "$DIST_DIR"

    blue "Linux:"
    build_one linux   amd64 linux-amd64
    build_one linux   arm64 linux-arm64

    blue "Windows:"
    build_one windows amd64 windows-amd64.exe

    blue "macOS:"
    build_one darwin  amd64 darwin-amd64
    build_one darwin  arm64 darwin-arm64
    build_universal

    echo
    bi_green "=== 编译完成 ===" "=== Build Complete ==="
    ls -lh "$DIST_DIR"/
}

# 仅编译 Linux / Build Linux only
build_linux() {
    bi_blue "=== 编译 Linux ===" "=== Build Linux ==="
    mkdir -p "$DIST_DIR"
    build_one linux amd64 linux-amd64
    build_one linux arm64 linux-arm64
    echo
    bi_green "=== 编译完成 ===" "=== Build Complete ==="
    ls -lh "$DIST_DIR"/${PROJECT}-linux-*
}

# 仅编译 Windows / Build Windows only
build_windows() {
    bi_blue "=== 编译 Windows ===" "=== Build Windows ==="
    mkdir -p "$DIST_DIR"
    build_one windows amd64 windows-amd64.exe
    echo
    bi_green "=== 编译完成 ===" "=== Build Complete ==="
    ls -lh "$DIST_DIR"/${PROJECT}-windows-*
}

# 仅编译 macOS / Build macOS only
build_darwin() {
    bi_blue "=== 编译 macOS ===" "=== Build macOS ==="
    mkdir -p "$DIST_DIR"
    build_one darwin amd64 darwin-amd64
    build_one darwin arm64 darwin-arm64
    build_universal
    echo
    bi_green "=== 编译完成 ===" "=== Build Complete ==="
    ls -lh "$DIST_DIR"/${PROJECT}-darwin-*
}

# 编译当前平台 / Build current platform
build_current() {
    bi_blue "=== 编译当前平台 ===" "=== Build Current Platform ==="
    go build -trimpath -ldflags "-s -w" -o "$PROJECT" .
    bi_green "=== 编译完成: ./${PROJECT} ===" "=== Build Complete: ./${PROJECT} ==="
    ls -lh "$PROJECT"
}

# 清理 / Clean
clean() {
    bi_blue "=== 清理 ${DIST_DIR}/ ===" "=== Clean ${DIST_DIR}/ ==="
    rm -rfv "$DIST_DIR"
    bi_green "=== 清理完成 ===" "=== Clean Complete ==="
}

# 主逻辑 / Main logic
case "${1:-all}" in
    all)     build_all ;;
    linux)   build_linux ;;
    windows) build_windows ;;
    darwin)  build_darwin ;;
    current) build_current ;;
    clean)   clean ;;
    -h|--help|help)
        cat <<EOF
用法 / Usage: ./build.sh [target]
  (无参数)   编译所有平台到 dist/                           Build all platforms to dist/
  all        编译所有平台到 dist/                           Build all platforms to dist/
  current    编译当前平台到当前目录                         Build current platform to current directory
  linux      编译 Linux (amd64 + arm64) 到 dist/            Build Linux (amd64 + arm64) to dist/
  windows    编译 Windows (amd64) 到 dist/                  Build Windows (amd64) to dist/
  darwin     编译 macOS (amd64 + arm64 + universal) 到 dist/  Build macOS (amd64 + arm64 + universal) to dist/
  clean      清理 dist/ 目录                                Clean dist/ directory
  help       显示此帮助信息                                 Show this help message
EOF
        ;;
    *)
        bi_red "未知目标: $1" "Unknown target: $1"
        bi "运行 ./build.sh help 查看用法" "Run ./build.sh help for usage"
        exit 1
        ;;
esac
