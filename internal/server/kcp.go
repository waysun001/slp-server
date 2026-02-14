package server

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
	"log"
	"net"
	"time"

	"github.com/smartlink/slp-server/internal/auth"
	"github.com/smartlink/slp-server/internal/config"
	"github.com/smartlink/slp-server/internal/protocol"
	"github.com/smartlink/slp-server/internal/proxy"
	"github.com/xtaci/kcp-go/v5"
)

type KCPServer struct {
	cfg         *config.Config
	authManager *auth.Manager
	listener    *kcp.Listener
	done        chan struct{}
}

func NewKCPServer(cfg *config.Config, authManager *auth.Manager) *KCPServer {
	return &KCPServer{
		cfg:         cfg,
		authManager: authManager,
		done:        make(chan struct{}),
	}
}

func (s *KCPServer) Start() error {
	// 创建加密块（使用简单的 AES 加密）
	// 实际使用时应该从配置读取密钥
	key := []byte("slp-kcp-key-0123") // 16 bytes for AES-128
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// FEC 配置
	dataShards := s.cfg.Listen.KCP.FECData
	parityShards := s.cfg.Listen.KCP.FECParity
	if dataShards == 0 {
		dataShards = 10
	}
	if parityShards == 0 {
		parityShards = 3
	}

	listener, err := kcp.ListenWithOptions(
		s.cfg.Listen.KCP.Addr,
		newBlockCrypt(block),
		dataShards,
		parityShards,
	)
	if err != nil {
		return err
	}

	s.listener = listener

	// 设置 KCP 参数
	listener.SetReadBuffer(4 * 1024 * 1024)
	listener.SetWriteBuffer(4 * 1024 * 1024)

	log.Printf("KCP listening on %s (FEC: %d+%d)", s.cfg.Listen.KCP.Addr, dataShards, parityShards)

	go s.accept()

	return nil
}

func (s *KCPServer) Stop() {
	close(s.done)
	if s.listener != nil {
		s.listener.Close()
	}
}

func (s *KCPServer) accept() {
	for {
		conn, err := s.listener.AcceptKCP()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				log.Printf("KCP accept error: %v", err)
				continue
			}
		}

		// 设置 KCP 参数 - 快速模式
		conn.SetStreamMode(true)
		conn.SetWriteDelay(false)
		conn.SetNoDelay(1, 10, 2, 1) // 快速模式
		conn.SetWindowSize(1024, 1024)
		conn.SetMtu(1350)
		conn.SetACKNoDelay(true)

		go s.handleConnection(conn)
	}
}

func (s *KCPServer) handleConnection(conn *kcp.UDPSession) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	log.Printf("New KCP connection from %s", remoteAddr)

	// 设置超时
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// 读取认证帧
	authFrame, err := protocol.ReadAuthFrame(conn)
	if err != nil {
		log.Printf("Failed to read auth frame: %v", err)
		return
	}

	// 验证 token
	tokenInfo, ok := s.authManager.Verify(authFrame.Token)
	if !ok {
		log.Printf("Auth failed for %s", remoteAddr)
		protocol.WriteAuthResponse(conn, false)
		return
	}

	log.Printf("Auth success: %s [%s]", tokenInfo.Name, remoteAddr)
	protocol.WriteAuthResponse(conn, true)

	// 清除超时
	conn.SetReadDeadline(time.Time{})

	// 处理数据
	s.handleData(conn, tokenInfo)
}

func (s *KCPServer) handleData(conn net.Conn, tokenInfo *auth.TokenInfo) {
	for {
		frame, err := protocol.ReadDataFrame(conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("Failed to read data frame: %v", err)
			}
			return
		}

		// 心跳
		if frame.Type == protocol.FrameHeartbeat {
			protocol.WriteHeartbeat(conn)
			continue
		}

		// 关闭
		if frame.Type == protocol.FrameClose {
			return
		}

		log.Printf("[%s] KCP Proxy to %s:%d", tokenInfo.Name, frame.Addr, frame.Port)

		// TCP 代理
		if frame.Type == protocol.FrameTCP {
			go func() {
				p, err := proxy.NewStreamProxy(conn, frame.Addr, frame.Port, tokenInfo.OutboundIP)
				if err != nil {
					log.Printf("Failed to create proxy: %v", err)
					return
				}
				p.Start()
			}()
			return // 连接已被代理接管
		}
	}
}

// blockCrypt 实现 kcp.BlockCrypt 接口
type blockCrypt struct {
	block cipher.Block
}

func newBlockCrypt(block cipher.Block) *blockCrypt {
	return &blockCrypt{block: block}
}

func (c *blockCrypt) Encrypt(dst, src []byte) {
	// 简单的 CTR 模式加密
	iv := make([]byte, c.block.BlockSize())
	stream := cipher.NewCTR(c.block, iv)
	stream.XORKeyStream(dst, src)
}

func (c *blockCrypt) Decrypt(dst, src []byte) {
	// CTR 模式解密（与加密相同）
	iv := make([]byte, c.block.BlockSize())
	stream := cipher.NewCTR(c.block, iv)
	stream.XORKeyStream(dst, src)
}

var _ kcp.BlockCrypt = (*blockCrypt)(nil)
