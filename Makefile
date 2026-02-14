.PHONY: build build-linux clean

# 版本信息
VERSION := 1.0.0
BUILD_TIME := $(shell date +%Y%m%d%H%M%S)
LDFLAGS := -s -w -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)

# 编译本地版本
build:
	go build -ldflags "$(LDFLAGS)" -o slp-server ./cmd/slp-server/

# 编译 Linux AMD64
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o slp-server-linux-amd64 ./cmd/slp-server/

# 编译 Linux ARM64
build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o slp-server-linux-arm64 ./cmd/slp-server/

# 编译所有平台
build-all: build-linux build-linux-arm64

# 清理
clean:
	rm -f slp-server slp-server-linux-*

# 运行测试
test:
	go test -v ./...

# 格式化代码
fmt:
	go fmt ./...

# 依赖整理
tidy:
	go mod tidy
