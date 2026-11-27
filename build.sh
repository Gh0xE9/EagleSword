#!/bin/bash

# EagleSword 跨平台构建脚本
# 支持 Linux、macOS、Windows 三个平台

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 项目信息
PROJECT_NAME="eaglesword"
VERSION=$(grep -E "^const VERSION" config/config.go | sed -E 's/.*"([^"]*)".*/\1/; s/^VERSION:[[:space:]]*//')
VERSION=${VERSION:-EG-0.0.1}
BUILD_DIR="dist"
MAIN_FILE="main.go"

echo -e "${BLUE}=== EagleSword 跨平台构建脚本 ===${NC}"
echo -e "${GREEN}版本: ${VERSION}${NC}"
echo ""

# 清理旧的构建文件
clean() {
    echo -e "${YELLOW}清理旧的构建文件...${NC}"
    rm -rf ${BUILD_DIR}
    mkdir -p ${BUILD_DIR}/{linux,macos,windows}
}

# 构建 Linux 版本
build_linux() {
    echo -e "${BLUE}构建 Linux (amd64)...${NC}"
    GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o ${BUILD_DIR}/linux/${PROJECT_NAME}-linux-amd64 ${MAIN_FILE}
    chmod +x ${BUILD_DIR}/linux/${PROJECT_NAME}-linux-amd64
    echo -e "${GREEN}✓ Linux (amd64) 构建完成${NC}"
    
    echo -e "${BLUE}构建 Linux (arm64)...${NC}"
    GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o ${BUILD_DIR}/linux/${PROJECT_NAME}-linux-arm64 ${MAIN_FILE}
    chmod +x ${BUILD_DIR}/linux/${PROJECT_NAME}-linux-arm64
    echo -e "${GREEN}✓ Linux (arm64) 构建完成${NC}"
}

# 构建 macOS 版本
build_macos() {
    echo -e "${BLUE}构建 macOS (amd64)...${NC}"
    GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o ${BUILD_DIR}/macos/${PROJECT_NAME}-macos-amd64 ${MAIN_FILE}
    chmod +x ${BUILD_DIR}/macos/${PROJECT_NAME}-macos-amd64
    echo -e "${GREEN}✓ macOS (amd64) 构建完成${NC}"
    
    echo -e "${BLUE}构建 macOS (arm64)...${NC}"
    GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o ${BUILD_DIR}/macos/${PROJECT_NAME}-macos-arm64 ${MAIN_FILE}
    chmod +x ${BUILD_DIR}/macos/${PROJECT_NAME}-macos-arm64
    echo -e "${GREEN}✓ macOS (arm64) 构建完成${NC}"
}

# 构建 Windows 版本
build_windows() {
    echo -e "${BLUE}构建 Windows (amd64)...${NC}"
    GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o ${BUILD_DIR}/windows/${PROJECT_NAME}-windows-amd64.exe ${MAIN_FILE}
    echo -e "${GREEN}✓ Windows (amd64) 构建完成${NC}"
    
    echo -e "${BLUE}构建 Windows (arm64)...${NC}"
    GOOS=windows GOARCH=arm64 go build -ldflags="-s -w" -o ${BUILD_DIR}/windows/${PROJECT_NAME}-windows-arm64.exe ${MAIN_FILE}
    echo -e "${GREEN}✓ Windows (arm64) 构建完成${NC}"
}

# 显示构建信息
show_info() {
    echo ""
    echo -e "${GREEN}=== 构建完成 ===${NC}"
    echo -e "${BLUE}构建目录: ${BUILD_DIR}/${NC}"
    echo ""
    echo -e "${YELLOW}Linux:${NC}"
    ls -lh ${BUILD_DIR}/linux/ 2>/dev/null || echo "  无文件"
    echo ""
    echo -e "${YELLOW}macOS:${NC}"
    ls -lh ${BUILD_DIR}/macos/ 2>/dev/null || echo "  无文件"
    echo ""
    echo -e "${YELLOW}Windows:${NC}"
    ls -lh ${BUILD_DIR}/windows/ 2>/dev/null || echo "  无文件"
}

# 主函数
main() {
    # 检查参数
    if [ "$1" == "clean" ]; then
        clean
        exit 0
    fi
    
    if [ "$1" == "linux" ]; then
        clean
        build_linux
        show_info
        exit 0
    fi
    
    if [ "$1" == "macos" ]; then
        clean
        build_macos
        show_info
        exit 0
    fi
    
    if [ "$1" == "windows" ]; then
        clean
        build_windows
        show_info
        exit 0
    fi
    
    # 默认构建所有平台
    if [ -z "$1" ] || [ "$1" == "all" ]; then
        clean
        build_linux
        build_macos
        build_windows
        show_info
        exit 0
    fi
    
    # 显示帮助
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  all      - 构建所有平台（默认）"
    echo "  linux    - 仅构建 Linux 版本"
    echo "  macos    - 仅构建 macOS 版本"
    echo "  windows  - 仅构建 Windows 版本"
    echo "  clean    - 清理构建文件"
    echo ""
}

main "$@"

