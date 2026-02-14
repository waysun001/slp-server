package server

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/smartlink/slp-server/internal/auth"
	"github.com/smartlink/slp-server/internal/config"
	"github.com/smartlink/slp-server/internal/protocol"
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
}

func NewWebSocketServer(cfg *config.Config, authManager *auth.Manager) *WebSocketServer {
	return &WebSocketServer{
		cfg:         cfg,
		authManager: authManager,
	}
}

func (s *WebSocketServer) Start() error {
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

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// 读取认证帧
	_, authData, err := conn.ReadMessage()
	if err != nil {
		log.Printf("Failed to read auth: %v", err)
		return
	}

	if len(authData) < 4 {
		return
	}

	if authData[0] != protocol.Version {
		return
	}

	tokenLen := int(authData[2])<<8 | int(authData[3])
	if len(authData) < 4+tokenLen {
		return
	}

	token := string(authData[4 : 4+tokenLen])

	tokenInfo, ok := s.authManager.Verify(token)
	if !ok {
		log.Printf("Auth failed for %s", remoteAddr)
		conn.WriteMessage(websocket.BinaryMessage, []byte{protocol.Version, 0x00})
		return
	}

	log.Printf("Auth success: %s [%s]", tokenInfo.Name, remoteAddr)
	conn.WriteMessage(websocket.BinaryMessage, []byte{protocol.Version, 0x01})

	conn.SetReadDeadline(time.Time{})

	// 处理代理请求
	s.handleProxy(conn, tokenInfo)
}

func (s *WebSocketServer) handleProxy(wsConn *websocket.Conn, tokenInfo *auth.TokenInfo) {
	for {
		messageType, data, err := wsConn.ReadMessage()
		if err != nil {
			return
		}

		if messageType != websocket.BinaryMessage || len(data) < 3 {
			continue
		}

		frameType := data[0]

		if frameType == protocol.FrameHeartbeat {
			wsConn.WriteMessage(websocket.BinaryMessage, []byte{protocol.FrameHeartbeat, 0x00, 0x00})
			continue
		}

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
		case protocol.AddrIPv4:
			if addrLen == 4 {
				addr = fmt.Sprintf("%d.%d.%d.%d", data[3], data[4], data[5], data[6])
			}
		case protocol.AddrDomain:
			addr = string(data[3 : 3+addrLen])
		}

		port := uint16(data[3+addrLen])<<8 | uint16(data[3+addrLen+1])

		log.Printf("[%s] WS Proxy to %s:%d", tokenInfo.Name, addr, port)

		// 连接目标并开始双向转发
		go s.proxyToTarget(wsConn, addr, port, tokenInfo.OutboundIP)
		return // 一个 WebSocket 连接只处理一个代理请求
	}
}

func (s *WebSocketServer) proxyToTarget(wsConn *websocket.Conn, addr string, port uint16, outboundIP string) {
	target := fmt.Sprintf("%s:%d", addr, port)

	// 连接目标
	var dialer net.Dialer
	if outboundIP != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(outboundIP)}
	}
	dialer.Timeout = 10 * time.Second

	targetConn, err := dialer.Dial("tcp", target)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", target, err)
		return
	}
	defer targetConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	// WebSocket -> Target
	go func() {
		defer wg.Done()
		for {
			_, data, err := wsConn.ReadMessage()
			if err != nil {
				return
			}
			if _, err := targetConn.Write(data); err != nil {
				return
			}
		}
	}()

	// Target -> WebSocket
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := targetConn.Read(buf)
			if err != nil {
				return
			}
			if err := wsConn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
				return
			}
		}
	}()

	wg.Wait()
}
