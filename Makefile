# Go 参数
BINARY_NAME=eaglesword
VERSION?=1.5.2
BUILD_TIME=$(shell date +%FT%T%z)
GIT_COMMIT=$(shell git rev-parse HEAD)
GIT_BRANCH=$(shell git rev-parse --abbrev-ref HEAD)

# Go 构建参数
GO_LDFLAGS=-ldflags "\
	-X main.Version=$(VERSION) \
	-X main.BuildTime=$(BUILD_TIME) \
	-X main.GitCommit=$(GIT_COMMIT) \
	-X main.GitBranch=$(GIT_BRANCH) \
	-s -w"

# 构建目录
BUILD_DIR=bin
DIST_DIR=dist

# 默认目标
.DEFAULT_GOAL := help

## help: 显示所有可用的命令
help:
	@echo "可用命令:"
	@echo
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'

## build: 构建当前平台的二进制文件
build:
	@echo "构建 $(BINARY_NAME) 当前平台..."
	@mkdir -p $(BUILD_DIR)
	go build $(GO_LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .

## build-all: 构建所有平台的二进制文件
build-all: build-linux build-darwin build-windows

## build-linux: 构建 Linux 平台的二进制文件
build-linux:
	@echo "构建 Linux 平台..."
	@mkdir -p $(DIST_DIR)/linux
	GOOS=linux GOARCH=amd64 go build $(GO_LDFLAGS) -o $(DIST_DIR)/linux/$(BINARY_NAME)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build $(GO_LDFLAGS) -o $(DIST_DIR)/linux/$(BINARY_NAME)-linux-arm64 .

## build-darwin: 构建 macOS 平台的二进制文件
build-darwin:
	@echo "构建 macOS 平台..."
	@mkdir -p $(DIST_DIR)/macos
	GOOS=darwin GOARCH=amd64 go build $(GO_LDFLAGS) -o $(DIST_DIR)/macos/$(BINARY_NAME)-macos-amd64 .
	GOOS=darwin GOARCH=arm64 go build $(GO_LDFLAGS) -o $(DIST_DIR)/macos/$(BINARY_NAME)-macos-arm64 .

## build-windows: 构建 Windows 平台的二进制文件
build-windows:
	@echo "构建 Windows 平台..."
	@mkdir -p $(DIST_DIR)/windows
	GOOS=windows GOARCH=amd64 go build $(GO_LDFLAGS) -o $(DIST_DIR)/windows/$(BINARY_NAME)-windows-amd64.exe .
	GOOS=windows GOARCH=arm64 go build $(GO_LDFLAGS) -o $(DIST_DIR)/windows/$(BINARY_NAME)-windows-arm64.exe .

## build-docker: 构建 Docker 镜像
build-docker:
	@echo "构建 Docker 镜像..."
	docker build -t $(BINARY_NAME):$(VERSION) .
	docker tag $(BINARY_NAME):$(VERSION) $(BINARY_NAME):latest

## clean: 清理构建文件
clean:
	@echo "清理构建文件..."
	rm -rf $(BUILD_DIR) $(DIST_DIR)

## test: 运行测试
test:
	@echo "运行测试..."
	go test -v ./...

## test-coverage: 运行测试并生成覆盖率报告
test-coverage:
	@echo "运行测试覆盖率..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

## lint: 运行代码检查
lint:
	@echo "运行代码检查..."
	@if command -v golangci-lint >/dev/null; then \
		golangci-lint run; \
	else \
		echo "golangci-lint 未安装，跳过代码检查"; \
		echo "安装命令: curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.54.2"; \
	fi

## fmt: 格式化代码
fmt:
	@echo "格式化代码..."
	go fmt ./...

## vet: 运行 go vet 检查
vet:
	@echo "运行 go vet..."
	go vet ./...

## install: 安装依赖
install:
	@echo "安装依赖..."
	go mod download
	go mod tidy

## run: 运行项目
run:
	@echo "运行项目..."
	go run main.go

## release: 创建发布版本（包含所有平台）
release: clean build-all
	@echo "创建发布版本 $(VERSION)..."
	@mkdir -p release
	cp -r $(DIST_DIR)/* release/
	cd release && find . -type f -exec sh -c 'sha256sum "{}" > "{}.sha256"' \;
	@echo "发布文件已创建在 release/ 目录"

## docker-run: 在 Docker 中运行
docker-run: build-docker
	@echo "在 Docker 中运行..."
	docker run -p 8080:8080 $(BINARY_NAME):latest

## cross-compile: 交叉编译所有支持的平台
cross-compile: clean
	@echo "交叉编译所有平台..."
	@mkdir -p $(DIST_DIR)
	
	# Linux
	GOOS=linux GOARCH=amd64 go build $(GO_LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build $(GO_LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-linux-arm64 .
	GOOS=linux GOARCH=386 go build $(GO_LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-linux-386 .
	GOOS=linux GOARCH=arm go build $(GO_LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-linux-arm .
	
	# macOS
	GOOS=darwin GOARCH=amd64 go build $(GO_LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build $(GO_LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-darwin-arm64 .
	
	# Windows
	GOOS=windows GOARCH=amd64 go build $(GO_LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-windows-amd64.exe .
	GOOS=windows GOARCH=386 go build $(GO_LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-windows-386.exe .
	
	# FreeBSD
	GOOS=freebsd GOARCH=amd64 go build $(GO_LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-freebsd-amd64 .
	
	@echo "交叉编译完成！"

## list-platforms: 列出所有支持的平台
list-platforms:
	@echo "支持的 Go 平台:"
	@echo "Linux:   amd64, arm64, 386, arm"
	@echo "macOS:   amd64, arm64"
	@echo "Windows: amd64, 386"
	@echo "FreeBSD: amd64"

## install-tools: 安装开发工具
install-tools:
	@echo "安装开发工具..."
	# 安装 golangci-lint
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	# 安装 air (热重载)
	go install github.com/cosmtrek/air@latest
	# 安装 richgo (彩色测试输出)
	go install github.com/kyoh86/richgo@latest

## dev: 开发模式（使用 air 热重载）
dev:
	@if command -v air >/dev/null; then \
		air; \
	else \
		echo "air 未安装，使用普通运行模式"; \
		echo "安装命令: go install github.com/cosmtrek/air@latest"; \
		go run main.go; \
	fi

.PHONY: help build build-all build-linux build-darwin build-windows clean test lint fmt vet install run release docker-run cross-compile list-platforms install-tools dev test-coverage build-docker
