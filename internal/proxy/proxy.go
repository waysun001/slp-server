package proxy

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

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
	
	return dialer.Dial(network, address)
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
		io.Copy(targetConn, clientConn)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// target -> client
	go func() {
		defer wg.Done()
		io.Copy(clientConn, targetConn)
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

// StreamProxy 流式代理（用于 QUIC stream）
type StreamProxy struct {
	stream     io.ReadWriteCloser
	targetConn net.Conn
	done       chan struct{}
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
		done:       make(chan struct{}),
		outboundIP: outboundIP,
	}, nil
}

func (p *StreamProxy) Start() {
	var wg sync.WaitGroup
	wg.Add(2)
	
	go func() {
		defer wg.Done()
		p.copyToTarget()
	}()
	
	go func() {
		defer wg.Done()
		p.copyFromTarget()
	}()
	
	wg.Wait()
}

func (p *StreamProxy) copyToTarget() {
	_, err := io.Copy(p.targetConn, p.stream)
	if err != nil {
		log.Printf("copy to target error: %v", err)
	}
	// 关闭目标连接的写方向
	if tc, ok := p.targetConn.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
}

func (p *StreamProxy) copyFromTarget() {
	_, err := io.Copy(p.stream, p.targetConn)
	if err != nil {
		log.Printf("copy from target error: %v", err)
	}
	p.stream.Close()
}

func (p *StreamProxy) Close() {
	select {
	case <-p.done:
		return
	default:
		close(p.done)
		p.stream.Close()
		p.targetConn.Close()
	}
}
