# SLP Server

SmartLink Protocol 服务端 - 高性能代理隧道服务器

## 功能

- QUIC 传输（默认，抗丢包）
- WebSocket 传输（过 CDN 防墙）
- KCP + FEC 传输（极端弱网）
- Token 认证
- 流量统计

## 编译

```bash
# 安装 Go 1.21+
# https://go.dev/dl/

# 编译
go build -o slp-server ./cmd/slp-server/

# 交叉编译 Linux
GOOS=linux GOARCH=amd64 go build -o slp-server-linux-amd64 ./cmd/slp-server/
```

## 部署

```bash
# 1. 上传二进制
scp slp-server-linux-amd64 root@your-vps:/usr/local/bin/slp-server

# 2. 申请 TLS 证书
apt install certbot
certbot certonly --standalone -d proxy.example.com

# 3. 创建配置
mkdir -p /etc/slp
cat > /etc/slp/config.yaml << 'EOF'
server:
  name: "us-west-1"

listen:
  quic:
    enabled: true
    addr: ":443"

tls:
  cert: "/etc/letsencrypt/live/proxy.example.com/fullchain.pem"
  key: "/etc/letsencrypt/live/proxy.example.com/privkey.pem"

auth:
  tokens:
    - name: "router-01"
      token: "your-secure-token-here"
      bandwidth: 0
EOF

# 4. 创建 systemd 服务
cat > /etc/systemd/system/slp-server.service << 'EOF'
[Unit]
Description=SmartLink Protocol Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/slp-server -c /etc/slp/config.yaml
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

# 5. 启动
systemctl daemon-reload
systemctl enable --now slp-server
systemctl status slp-server
```

## 配置说明

```yaml
server:
  name: "节点名称"

listen:
  quic:
    enabled: true
    addr: ":443"          # QUIC 监听地址
  websocket:
    enabled: false
    addr: ":8443"
    path: "/ws"
  kcp:
    enabled: false
    addr: ":4000"
    fec_data: 10          # FEC 数据包数量
    fec_parity: 3         # FEC 校验包数量

tls:
  cert: "证书路径"
  key: "私钥路径"

auth:
  tokens:
    - name: "客户端名称"
      token: "认证令牌"
      bandwidth: 0        # 带宽限制 (Mbps)，0=无限

log:
  level: "info"           # debug/info/warn/error
  file: ""                # 日志文件，空=stdout

stats:
  enabled: false
  api_addr: "127.0.0.1:9090"
```

## 防火墙

```bash
# 开放 QUIC 端口 (UDP)
ufw allow 443/udp

# 开放 WebSocket 端口 (TCP)
ufw allow 8443/tcp

# 开放 KCP 端口 (UDP)
ufw allow 4000/udp
```

## 日志

```bash
# 查看日志
journalctl -u slp-server -f

# 查看最近 100 行
journalctl -u slp-server -n 100
```
