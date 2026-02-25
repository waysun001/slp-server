package proxy

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/smartlink/slp-server/internal/protocol"
)

// copyBufPool 64KB 池化缓冲区，减少 io.Copy 系统调用开销
var copyBufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 64*1024)
		return &buf
	},
}

func getCopyBuf() []byte {
	return *(copyBufPool.Get().(*[]byte))
}

func putCopyBuf(buf []byte) {
	copyBufPool.Put(&buf)
}

// Dialer 带出口 IP 的拨号器
type Dialer struct {
	OutboundIP string
}

// Dial 使用指定出口 IP 连接目标
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	var localAddr net.Addr

	if d.OutboundIP != "" {
		switch network {
		case "tcp", "tcp4", "tcp6":
			localAddr = &net.TCPAddr{IP: net.ParseIP(d.OutboundIP)}
		case "udp", "udp4", "udp6":
			localAddr = &net.UDPAddr{IP: net.ParseIP(d.OutboundIP)}
		}
	}

	dialer := &net.Dialer{
		LocalAddr: localAddr,
		Timeout:   10 * time.Second,
	}

	conn, err := dialer.Dial(network, address)
	if err != nil {
		return nil, err
	}

	// TCP 连接调优：禁用 Nagle、增大 socket 缓冲区
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetReadBuffer(2 * 1024 * 1024)  // 2MB
		tc.SetWriteBuffer(2 * 1024 * 1024) // 2MB
	}

	return conn, nil
}

// TCPProxy 处理 TCP 代理转发
func TCPProxy(clientConn io.ReadWriteCloser, targetAddr string, targetPort uint16, outboundIP string) error {
	target := fmt.Sprintf("%s:%d", targetAddr, targetPort)

	// 使用指定出口 IP 连接目标服务器
	dialer := &Dialer{OutboundIP: outboundIP}
	targetConn, err := dialer.Dial("tcp", target)
	if err != nil {
		return fmt.Errorf("failed to connect target %s: %w", target, err)
	}
	defer targetConn.Close()

	if outboundIP != "" {
		log.Printf("Connected to %s via %s", target, outboundIP)
	}

	// 双向转发
	var wg sync.WaitGroup
	wg.Add(2)

	// client -> target
	go func() {
		defer wg.Done()
		buf := getCopyBuf()
		io.CopyBuffer(targetConn, clientConn, buf)
		putCopyBuf(buf)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// target -> client
	go func() {
		defer wg.Done()
		buf := getCopyBuf()
		io.CopyBuffer(clientConn, targetConn, buf)
		putCopyBuf(buf)
	}()

	wg.Wait()
	return nil
}

// UDPProxy 处理 UDP 代理转发
func UDPProxy(data []byte, targetAddr string, targetPort uint16, responseCh chan<- []byte) error {
	target := fmt.Sprintf("%s:%d", targetAddr, targetPort)

	// 创建 UDP 连接
	conn, err := net.Dial("udp", target)
	if err != nil {
		return fmt.Errorf("failed to dial UDP %s: %w", target, err)
	}
	defer conn.Close()

	// 设置超时
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// 发送数据
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("failed to write UDP: %w", err)
	}

	// 读取响应
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read UDP response: %w", err)
	}

	responseCh <- buf[:n]
	return nil
}

// idleTimeoutReader wraps a reader with deadline-based idle timeout.
type idleTimeoutReader struct {
	reader      io.Reader
	setDeadline func(time.Time) error
	timeout     time.Duration
}

func (r *idleTimeoutReader) Read(p []byte) (int, error) {
	if err := r.setDeadline(time.Now().Add(r.timeout)); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

// StreamProxy 流式代理（用于 QUIC stream）
type StreamProxy struct {
	stream     io.ReadWriteCloser
	targetConn net.Conn
	closeOnce  sync.Once
	outboundIP string
}

func NewStreamProxy(stream io.ReadWriteCloser, targetAddr string, targetPort uint16, outboundIP string) (*StreamProxy, error) {
	target := fmt.Sprintf("%s:%d", targetAddr, targetPort)

	dialer := &Dialer{OutboundIP: outboundIP}
	targetConn, err := dialer.Dial("tcp", target)
	if err != nil {
		return nil, err
	}

	if outboundIP != "" {
		log.Printf("Stream proxy to %s via %s", target, outboundIP)
	}

	return &StreamProxy{
		stream:     stream,
		targetConn: targetConn,
		outboundIP: outboundIP,
	}, nil
}

func (p *StreamProxy) Start() {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		p.copyToTarget()
		// copyToTarget 只做 CloseWrite（半关闭）
		// target 收到 FIN 后完成发送 → copyFromTarget 自然结束
		// 不能在此调用 p.Close()，否则会杀死正在读响应的 copyFromTarget
	}()

	go func() {
		defer wg.Done()
		p.copyFromTarget()
		// copyFromTarget 结束后关闭 stream → 唤醒 copyToTarget
	}()

	wg.Wait()
	// 双向都结束后确保资源完全释放（防止 targetConn 泄漏）
	p.Close()
}

func (p *StreamProxy) copyToTarget() {
	const idleTimeout = 60 * time.Second

	// Apply idle timeout to stream read if it supports SetReadDeadline
	var reader io.Reader = p.stream
	if dl, ok := p.stream.(interface{ SetReadDeadline(time.Time) error }); ok {
		reader = &idleTimeoutReader{reader: p.stream, setDeadline: dl.SetReadDeadline, timeout: idleTimeout}
	}

	buf := getCopyBuf()
	_, err := io.CopyBuffer(p.targetConn, reader, buf)
	putCopyBuf(buf)
	if err != nil {
		log.Printf("copy to target error: %v", err)
	}
	// 关闭目标连接的写方向
	if tc, ok := p.targetConn.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
}

func (p *StreamProxy) copyFromTarget() {
	const idleTimeout = 60 * time.Second

	// Apply idle timeout to target conn read
	reader := &idleTimeoutReader{
		reader:      p.targetConn,
		setDeadline: p.targetConn.SetReadDeadline,
		timeout:     idleTimeout,
	}

	buf := getCopyBuf()
	_, err := io.CopyBuffer(p.stream, reader, buf)
	putCopyBuf(buf)
	if err != nil {
		log.Printf("copy from target error: %v", err)
	}
	p.stream.Close()
}

func (p *StreamProxy) Close() {
	p.closeOnce.Do(func() {
		p.stream.Close()
		p.targetConn.Close()
	})
}

// UDPStreamProxy 通过流式连接代理 UDP 流量
// stream 使用 [2字节长度][载荷] 分帧，UDP socket 使用原生数据报
func UDPStreamProxy(stream io.ReadWriteCloser, targetAddr string, targetPort uint16, outboundIP string) error {
	target := fmt.Sprintf("%s:%d", targetAddr, targetPort)

	dialer := &Dialer{OutboundIP: outboundIP}
	udpConn, err := dialer.Dial("udp", target)
	if err != nil {
		return fmt.Errorf("failed to dial UDP %s: %w", target, err)
	}
	defer udpConn.Close()
	defer stream.Close()

	log.Printf("Proxy UDP to %s", target)

	const idleTimeout = 60 * time.Second
	done := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(2)

	// stream -> UDP socket：读取长度前缀帧，发送原生数据报
	go func() {
		defer wg.Done()
		for {
			pkt, err := protocol.ReadUDPPacket(stream)
			if err != nil {
				break
			}
			udpConn.SetWriteDeadline(time.Now().Add(idleTimeout))
			if _, err := udpConn.Write(pkt); err != nil {
				break
			}
		}
		select {
		case <-done:
		default:
			close(done)
		}
	}()

	// UDP socket -> stream：读取原生数据报，写入长度前缀帧
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			udpConn.SetReadDeadline(time.Now().Add(idleTimeout))
			n, err := udpConn.Read(buf)
			if err != nil {
				break
			}
			if err := protocol.WriteUDPPacket(stream, buf[:n]); err != nil {
				break
			}
		}
		select {
		case <-done:
		default:
			close(done)
		}
	}()

	// 等待任一方向结束
	<-done
	// 关闭连接以唤醒阻塞的另一方
	udpConn.Close()
	stream.Close()
	wg.Wait()
	return nil
}
