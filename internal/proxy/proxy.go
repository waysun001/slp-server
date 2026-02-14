package proxy

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// TCPProxy 处理 TCP 代理转发
func TCPProxy(clientConn io.ReadWriteCloser, targetAddr string, targetPort uint16) error {
	target := fmt.Sprintf("%s:%d", targetAddr, targetPort)

	// 连接目标服务器
	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect target %s: %w", target, err)
	}
	defer targetConn.Close()

	// 双向转发
	var wg sync.WaitGroup
	wg.Add(2)

	// client -> target
	go func() {
		defer wg.Done()
		io.Copy(targetConn, clientConn)
		targetConn.(*net.TCPConn).CloseWrite()
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
}

func NewStreamProxy(stream io.ReadWriteCloser, targetAddr string, targetPort uint16) (*StreamProxy, error) {
	target := fmt.Sprintf("%s:%d", targetAddr, targetPort)

	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return nil, err
	}

	return &StreamProxy{
		stream:     stream,
		targetConn: targetConn,
		done:       make(chan struct{}),
	}, nil
}

func (p *StreamProxy) Start() {
	go p.copyToTarget()
	go p.copyFromTarget()
}

func (p *StreamProxy) copyToTarget() {
	defer p.Close()
	_, err := io.Copy(p.targetConn, p.stream)
	if err != nil {
		log.Printf("copy to target error: %v", err)
	}
}

func (p *StreamProxy) copyFromTarget() {
	defer p.Close()
	_, err := io.Copy(p.stream, p.targetConn)
	if err != nil {
		log.Printf("copy from target error: %v", err)
	}
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
