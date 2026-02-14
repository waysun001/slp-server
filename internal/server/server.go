package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/smartlink/slp-server/internal/auth"
	"github.com/smartlink/slp-server/internal/config"
	"github.com/smartlink/slp-server/internal/protocol"
	"github.com/smartlink/slp-server/internal/proxy"
)

type Server struct {
	cfg         *config.Config
	authManager *auth.Manager
	quicLn      *quic.Listener
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

func New(cfg *config.Config) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())

	return &Server{
		cfg:         cfg,
		authManager: auth.NewManager(&cfg.Auth),
		ctx:         ctx,
		cancel:      cancel,
	}, nil
}

func (s *Server) Start() error {
	// 启动 QUIC 监听
	if s.cfg.Listen.QUIC.Enabled {
		if err := s.startQUIC(); err != nil {
			return fmt.Errorf("failed to start QUIC: %w", err)
		}
	}

	// 启动 WebSocket 监听
	if s.cfg.Listen.WebSocket.Enabled {
		ws := NewWebSocketServer(s.cfg, s.authManager)
		if err := ws.Start(); err != nil {
			return fmt.Errorf("failed to start WebSocket: %w", err)
		}
	}

	// 启动 KCP 监听
	if s.cfg.Listen.KCP.Enabled {
		kcp := NewKCPServer(s.cfg, s.authManager)
		if err := kcp.Start(); err != nil {
			return fmt.Errorf("failed to start KCP: %w", err)
		}
	}

	return nil
}

func (s *Server) Stop() {
	s.cancel()
	if s.quicLn != nil {
		s.quicLn.Close()
	}
	s.wg.Wait()
}

func (s *Server) startQUIC() error {
	// 加载 TLS 证书
	cert, err := tls.LoadX509KeyPair(s.cfg.TLS.Cert, s.cfg.TLS.Key)
	if err != nil {
		return fmt.Errorf("failed to load TLS cert: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"slp", "h3"}, // 伪装成 HTTP/3
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
	}

	ln, err := quic.ListenAddr(s.cfg.Listen.QUIC.Addr, tlsConfig, quicConfig)
	if err != nil {
		return err
	}
	s.quicLn = ln

	log.Printf("QUIC listening on %s", s.cfg.Listen.QUIC.Addr)

	s.wg.Add(1)
	go s.acceptQUIC()

	return nil
}

func (s *Server) acceptQUIC() {
	defer s.wg.Done()

	for {
		conn, err := s.quicLn.Accept(s.ctx)
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				log.Printf("QUIC accept error: %v", err)
				continue
			}
		}

		go s.handleQUICConnection(conn)
	}
}

func (s *Server) handleQUICConnection(conn quic.Connection) {
	defer conn.CloseWithError(0, "connection closed")

	remoteAddr := conn.RemoteAddr().String()
	log.Printf("New QUIC connection from %s", remoteAddr)

	// 接受第一个 stream 用于认证
	stream, err := conn.AcceptStream(s.ctx)
	if err != nil {
		log.Printf("Failed to accept auth stream: %v", err)
		return
	}

	// 读取认证帧
	authFrame, err := protocol.ReadAuthFrame(stream)
	if err != nil {
		log.Printf("Failed to read auth frame: %v", err)
		stream.Close()
		return
	}

	// 验证 token
	tokenInfo, ok := s.authManager.Verify(authFrame.Token)
	if !ok {
		log.Printf("Auth failed for %s", remoteAddr)
		protocol.WriteAuthResponse(stream, false)
		stream.Close()
		return
	}

	log.Printf("Auth success: %s [%s]", tokenInfo.Name, remoteAddr)
	protocol.WriteAuthResponse(stream, true)
	stream.Close()

	// 处理后续的数据 stream
	for {
		dataStream, err := conn.AcceptStream(s.ctx)
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				log.Printf("Connection closed: %s", remoteAddr)
				return
			}
		}

		go s.handleDataStream(dataStream, tokenInfo)
	}
}

func (s *Server) handleDataStream(stream quic.Stream, tokenInfo *auth.TokenInfo) {
	defer stream.Close()

	// 读取数据帧头部（目标地址）
	frame, err := protocol.ReadDataFrame(stream)
	if err != nil {
		if err != io.EOF {
			log.Printf("Failed to read data frame: %v", err)
		}
		return
	}

	// 心跳帧
	if frame.Type == protocol.FrameHeartbeat {
		protocol.WriteHeartbeat(stream)
		return
	}

	// 关闭帧
	if frame.Type == protocol.FrameClose {
		return
	}

	log.Printf("[%s] Proxy to %s:%d (outbound: %s)", tokenInfo.Name, frame.Addr, frame.Port, tokenInfo.OutboundIP)

	// 创建代理，使用指定的出口 IP
	p, err := proxy.NewStreamProxy(stream, frame.Addr, frame.Port, tokenInfo.OutboundIP)
	if err != nil {
		log.Printf("Failed to create proxy: %v", err)
		return
	}

	p.Start()
}
