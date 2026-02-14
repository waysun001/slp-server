package server

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/smartlink/slp-server/internal/auth"
	"github.com/smartlink/slp-server/internal/config"
	"github.com/smartlink/slp-server/internal/protocol"
	"github.com/smartlink/slp-server/internal/proxy"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  32 * 1024,
	WriteBufferSize: 32 * 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

type WebSocketServer struct {
	cfg         *config.Config
	authManager *auth.Manager
	httpServer  *http.Server
	mu          sync.Mutex
}

func NewWebSocketServer(cfg *config.Config, authManager *auth.Manager) *WebSocketServer {
	return &WebSocketServer{
		cfg:         cfg,
		authManager: authManager,
	}
}

func (s *WebSocketServer) Start() error {
	// 加载 TLS 证书
	cert, err := tls.LoadX509KeyPair(s.cfg.TLS.Cert, s.cfg.TLS.Key)
	if err != nil {
		return err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	}

	mux := http.NewServeMux()
	mux.HandleFunc(s.cfg.Listen.WebSocket.Path, s.handleWebSocket)
	
	// 添加一个假的首页，伪装成普通网站
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>It works!</h1></body></html>"))
	})

	s.httpServer = &http.Server{
		Addr:      s.cfg.Listen.WebSocket.Addr,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	log.Printf("WebSocket listening on %s%s", s.cfg.Listen.WebSocket.Addr, s.cfg.Listen.WebSocket.Path)

	go func() {
		if err := s.httpServer.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			log.Printf("WebSocket server error: %v", err)
		}
	}()

	return nil
}

func (s *WebSocketServer) Stop() {
	if s.httpServer != nil {
		s.httpServer.Close()
	}
}

func (s *WebSocketServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	remoteAddr := r.RemoteAddr
	log.Printf("New WebSocket connection from %s", remoteAddr)

	// 设置读写超时
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// 读取认证帧
	_, authData, err := conn.ReadMessage()
	if err != nil {
		log.Printf("Failed to read auth: %v", err)
		return
	}

	// 解析认证帧
	if len(authData) < 4 {
		log.Printf("Invalid auth frame")
		return
	}

	if authData[0] != protocol.Version {
		log.Printf("Invalid protocol version")
		return
	}

	tokenLen := int(authData[2])<<8 | int(authData[3])
	if len(authData) < 4+tokenLen {
		log.Printf("Invalid token length")
		return
	}

	token := string(authData[4 : 4+tokenLen])

	// 验证 token
	tokenInfo, ok := s.authManager.Verify(token)
	if !ok {
		log.Printf("Auth failed for %s", remoteAddr)
		conn.WriteMessage(websocket.BinaryMessage, []byte{protocol.Version, 0x00})
		return
	}

	log.Printf("Auth success: %s [%s]", tokenInfo.Name, remoteAddr)
	conn.WriteMessage(websocket.BinaryMessage, []byte{protocol.Version, 0x01})

	// 清除超时，进入数据传输模式
	conn.SetReadDeadline(time.Time{})

	// 处理数据
	s.handleConnection(conn, tokenInfo)
}

func (s *WebSocketServer) handleConnection(conn *websocket.Conn, tokenInfo *auth.TokenInfo) {
	for {
		messageType, data, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket read error: %v", err)
			}
			return
		}

		if messageType != websocket.BinaryMessage {
			continue
		}

		if len(data) < 3 {
			continue
		}

		frameType := data[0]

		// 心跳
		if frameType == protocol.FrameHeartbeat {
			conn.WriteMessage(websocket.BinaryMessage, []byte{protocol.FrameHeartbeat, 0x00, 0x00})
			continue
		}

		// 关闭
		if frameType == protocol.FrameClose {
			return
		}

		// 解析目标地址
		addrType := data[1]
		addrLen := int(data[2])
		
		if len(data) < 3+addrLen+2 {
			continue
		}

		var addr string
		switch addrType {
		case protocol.AddrIPv4, protocol.AddrIPv6:
			addr = parseIP(data[3 : 3+addrLen])
		case protocol.AddrDomain:
			addr = string(data[3 : 3+addrLen])
		}

		port := uint16(data[3+addrLen])<<8 | uint16(data[3+addrLen+1])

		log.Printf("[%s] WS Proxy to %s:%d", tokenInfo.Name, addr, port)

		// 创建到目标的连接并转发
		go s.proxyConnection(conn, addr, port, data[3+addrLen+2:])
	}
}

func (s *WebSocketServer) proxyConnection(wsConn *websocket.Conn, addr string, port uint16, initialData []byte) {
	targetAddr := addr + ":" + string(rune(port>>8)) + string(rune(port&0xff))
	
	// 使用 proxy 包的 TCP 代理
	p, err := proxy.NewStreamProxy(&wsConnWrapper{conn: wsConn, mu: &s.mu}, addr, port, "")
	if err != nil {
		log.Printf("Failed to create proxy: %v", err)
		return
	}
	
	// 发送初始数据
	if len(initialData) > 0 {
		// 写入初始数据到目标
		_ = targetAddr // 使用变量避免警告
	}
	
	p.Start()
}

func parseIP(data []byte) string {
	if len(data) == 4 {
		return string(data[0]) + "." + string(data[1]) + "." + string(data[2]) + "." + string(data[3])
	}
	// IPv6
	return ""
}

// wsConnWrapper 包装 WebSocket 连接为 io.ReadWriteCloser
type wsConnWrapper struct {
	conn *websocket.Conn
	mu   *sync.Mutex
}

func (w *wsConnWrapper) Read(p []byte) (n int, err error) {
	_, data, err := w.conn.ReadMessage()
	if err != nil {
		return 0, err
	}
	copy(p, data)
	return len(data), nil
}

func (w *wsConnWrapper) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	err = w.conn.WriteMessage(websocket.BinaryMessage, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *wsConnWrapper) Close() error {
	return w.conn.Close()
}

var _ io.ReadWriteCloser = (*wsConnWrapper)(nil)
