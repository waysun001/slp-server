#!/bin/bash
#
# SLP Server 一键部署脚本
# 用法: curl -fsSL https://raw.githubusercontent.com/yourrepo/slp-server/main/install.sh | bash
#

set -e

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# 检查 root
[[ $EUID -ne 0 ]] && log_error "请使用 root 用户运行此脚本"

# 系统信息
ARCH=$(uname -m)
case $ARCH in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    *)       log_error "不支持的架构: $ARCH" ;;
esac

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
[[ "$OS" != "linux" ]] && log_error "仅支持 Linux 系统"

# 配置
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/slp"
SERVICE_NAME="slp-server"
BINARY_NAME="slp-server"
GITHUB_REPO="smartlink/slp-server"
VERSION="${VERSION:-latest}"

# 生成随机 token
generate_token() {
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1
}

# 检查命令是否存在
check_command() {
    command -v "$1" &> /dev/null
}

# 安装依赖
install_deps() {
    log_info "检查依赖..."
    
    if check_command apt-get; then
        apt-get update -qq
        apt-get install -y -qq curl wget certbot
    elif check_command yum; then
        yum install -y -q curl wget certbot
    elif check_command dnf; then
        dnf install -y -q curl wget certbot
    else
        log_warn "无法自动安装依赖，请手动安装 curl wget certbot"
    fi
}

# 下载二进制
download_binary() {
    log_info "下载 SLP Server..."
    
    local url
    if [[ "$VERSION" == "latest" ]]; then
        url="https://github.com/${GITHUB_REPO}/releases/latest/download/${BINARY_NAME}-linux-${ARCH}"
    else
        url="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/${BINARY_NAME}-linux-${ARCH}"
    fi
    
    # 如果 GitHub 下载失败，尝试从备用地址
    if ! wget -q --show-progress -O "${INSTALL_DIR}/${BINARY_NAME}" "$url" 2>/dev/null; then
        log_warn "GitHub 下载失败，尝试本地编译..."
        compile_from_source
        return
    fi
    
    chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    log_info "已安装到 ${INSTALL_DIR}/${BINARY_NAME}"
}

# 从源码编译
compile_from_source() {
    log_info "从源码编译..."
    
    # 检查 Go
    if ! check_command go; then
        log_info "安装 Go..."
        wget -q https://go.dev/dl/go1.21.6.linux-${ARCH}.tar.gz
        rm -rf /usr/local/go
        tar -C /usr/local -xzf go1.21.6.linux-${ARCH}.tar.gz
        rm go1.21.6.linux-${ARCH}.tar.gz
        export PATH=$PATH:/usr/local/go/bin
    fi
    
    # 克隆并编译
    local tmp_dir=$(mktemp -d)
    cd "$tmp_dir"
    git clone --depth 1 "https://github.com/${GITHUB_REPO}.git" .
    CGO_ENABLED=0 go build -ldflags "-s -w" -o "${INSTALL_DIR}/${BINARY_NAME}" ./cmd/slp-server/
    cd -
    rm -rf "$tmp_dir"
    
    log_info "编译完成"
}

# 申请证书
setup_cert() {
    local domain="$1"
    
    if [[ -z "$domain" ]]; then
        log_warn "未指定域名，跳过证书申请"
        log_warn "请手动运行: certbot certonly --standalone -d your-domain.com"
        return 1
    fi
    
    log_info "申请 TLS 证书: $domain"
    
    # 停止占用 80 端口的服务
    systemctl stop nginx 2>/dev/null || true
    systemctl stop apache2 2>/dev/null || true
    
    certbot certonly --standalone --non-interactive --agree-tos \
        --register-unsafely-without-email -d "$domain" || {
        log_error "证书申请失败，请检查域名解析和防火墙"
    }
    
    log_info "证书申请成功"
    return 0
}

# 创建配置
create_config() {
    local domain="$1"
    local token="$2"
    local port="${3:-443}"
    
    mkdir -p "$CONFIG_DIR"
    
    local cert_path="/etc/letsencrypt/live/${domain}/fullchain.pem"
    local key_path="/etc/letsencrypt/live/${domain}/privkey.pem"
    
    # 如果没有证书，使用自签名
    if [[ ! -f "$cert_path" ]]; then
        log_warn "未找到 Let's Encrypt 证书，生成自签名证书..."
        cert_path="${CONFIG_DIR}/cert.pem"
        key_path="${CONFIG_DIR}/key.pem"
        
        openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
            -keyout "$key_path" -out "$cert_path" \
            -subj "/CN=${domain:-slp-server}" \
            -addext "subjectAltName=DNS:${domain:-localhost},IP:0.0.0.0" 2>/dev/null
    fi
    
    cat > "${CONFIG_DIR}/config.yaml" << EOF
server:
  name: "slp-$(hostname -s)"

listen:
  quic:
    enabled: true
    addr: ":${port}"
  websocket:
    enabled: true
    addr: ":$((port + 1))"
    path: "/ws"
  kcp:
    enabled: false
    addr: ":4000"
    fec_data: 10
    fec_parity: 3

tls:
  cert: "${cert_path}"
  key: "${key_path}"

auth:
  tokens:
    - name: "default"
      token: "${token}"
      bandwidth: 0

log:
  level: "info"
  file: ""

stats:
  enabled: true
  api_addr: "127.0.0.1:9090"
EOF

    log_info "配置已写入 ${CONFIG_DIR}/config.yaml"
}

# 创建 systemd 服务
create_service() {
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=SmartLink Protocol Server
Documentation=https://github.com/${GITHUB_REPO}
After=network.target

[Service]
Type=simple
User=root
ExecStart=${INSTALL_DIR}/${BINARY_NAME} -c ${CONFIG_DIR}/config.yaml
Restart=always
RestartSec=5
LimitNOFILE=65535

# 安全加固
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_info "systemd 服务已创建"
}

# 配置防火墙
setup_firewall() {
    local port="${1:-443}"
    
    log_info "配置防火墙..."
    
    if check_command ufw; then
        ufw allow ${port}/udp comment "SLP QUIC"
        ufw allow $((port + 1))/tcp comment "SLP WebSocket"
        ufw --force enable 2>/dev/null || true
    elif check_command firewall-cmd; then
        firewall-cmd --permanent --add-port=${port}/udp
        firewall-cmd --permanent --add-port=$((port + 1))/tcp
        firewall-cmd --reload
    else
        log_warn "未检测到防火墙，请手动开放端口 ${port}/udp 和 $((port + 1))/tcp"
    fi
}

# 启动服务
start_service() {
    log_info "启动服务..."
    systemctl enable "${SERVICE_NAME}"
    systemctl start "${SERVICE_NAME}"
    
    sleep 2
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        log_info "服务启动成功"
    else
        log_error "服务启动失败，请检查日志: journalctl -u ${SERVICE_NAME} -n 50"
    fi
}

# 显示信息
show_info() {
    local token="$1"
    local domain="$2"
    local port="${3:-443}"
    local ip=$(curl -s4 ip.sb || curl -s4 ifconfig.me || echo "YOUR_SERVER_IP")
    
    echo ""
    echo "=============================================="
    echo -e "${GREEN}SLP Server 安装完成！${NC}"
    echo "=============================================="
    echo ""
    echo "服务器信息:"
    echo "  IP:     ${ip}"
    echo "  域名:   ${domain:-未设置}"
    echo "  端口:   ${port} (QUIC), $((port + 1)) (WebSocket)"
    echo "  Token:  ${token}"
    echo ""
    echo "客户端配置:"
    echo "  server:    ${domain:-$ip}"
    echo "  port:      ${port}"
    echo "  transport: quic"
    echo "  token:     ${token}"
    echo ""
    echo "管理命令:"
    echo "  状态:  systemctl status ${SERVICE_NAME}"
    echo "  日志:  journalctl -u ${SERVICE_NAME} -f"
    echo "  重启:  systemctl restart ${SERVICE_NAME}"
    echo "  停止:  systemctl stop ${SERVICE_NAME}"
    echo ""
    echo "配置文件: ${CONFIG_DIR}/config.yaml"
    echo "=============================================="
}

# 卸载
uninstall() {
    log_info "卸载 SLP Server..."
    
    systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    rm -f "${INSTALL_DIR}/${BINARY_NAME}"
    rm -rf "${CONFIG_DIR}"
    systemctl daemon-reload
    
    log_info "卸载完成"
}

# 主函数
main() {
    local domain=""
    local token=""
    local port="443"
    local action="install"
    
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--domain)
                domain="$2"
                shift 2
                ;;
            -t|--token)
                token="$2"
                shift 2
                ;;
            -p|--port)
                port="$2"
                shift 2
                ;;
            --uninstall)
                action="uninstall"
                shift
                ;;
            -h|--help)
                echo "用法: $0 [选项]"
                echo ""
                echo "选项:"
                echo "  -d, --domain DOMAIN   域名（用于申请证书）"
                echo "  -t, --token TOKEN     认证令牌（默认随机生成）"
                echo "  -p, --port PORT       监听端口（默认 443）"
                echo "  --uninstall           卸载"
                echo "  -h, --help            显示帮助"
                echo ""
                echo "示例:"
                echo "  $0 -d proxy.example.com"
                echo "  $0 -d proxy.example.com -t my-secret-token -p 8443"
                echo "  $0 --uninstall"
                exit 0
                ;;
            *)
                log_error "未知参数: $1"
                ;;
        esac
    done
    
    # 卸载
    if [[ "$action" == "uninstall" ]]; then
        uninstall
        exit 0
    fi
    
    # 生成 token
    [[ -z "$token" ]] && token=$(generate_token)
    
    echo ""
    echo "=============================================="
    echo "       SLP Server 一键部署脚本"
    echo "=============================================="
    echo ""
    
    # 安装流程
    install_deps
    download_binary
    
    # 申请证书（如果指定了域名）
    if [[ -n "$domain" ]]; then
        setup_cert "$domain"
    fi
    
    create_config "$domain" "$token" "$port"
    create_service
    setup_firewall "$port"
    start_service
    show_info "$token" "$domain" "$port"
}

main "$@"
