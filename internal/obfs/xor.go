package obfs

import (
	"crypto/sha256"
	"net"
	"sync"
)

// XORObfuscator 基于密钥的 XOR 混淆器
type XORObfuscator struct {
	key []byte
}

// NewXORObfuscator 创建混淆器
func NewXORObfuscator(password string) *XORObfuscator {
	hash := sha256.Sum256([]byte(password))
	return &XORObfuscator{key: hash[:]}
}

// Obfuscate 混淆数据
func (o *XORObfuscator) Obfuscate(data []byte) []byte {
	result := make([]byte, len(data))
	keyLen := len(o.key)
	for i, b := range data {
		result[i] = b ^ o.key[i%keyLen]
	}
	return result
}

// Deobfuscate 解混淆数据
func (o *XORObfuscator) Deobfuscate(data []byte) []byte {
	return o.Obfuscate(data)
}

// ObfsPacketConn 混淆的 UDP 连接
type ObfsPacketConn struct {
	net.PacketConn
	obfs *XORObfuscator
	mu   sync.Mutex
}

// NewObfsPacketConn 包装 UDP 连接
func NewObfsPacketConn(conn net.PacketConn, password string) *ObfsPacketConn {
	return &ObfsPacketConn{
		PacketConn: conn,
		obfs:       NewXORObfuscator(password),
	}
}

// ReadFrom 读取并解混淆
func (c *ObfsPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = c.PacketConn.ReadFrom(p)
	if err != nil {
		return
	}
	
	deobfs := c.obfs.Deobfuscate(p[:n])
	copy(p, deobfs)
	return n, addr, nil
}

// WriteTo 混淆后发送
func (c *ObfsPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	obfs := c.obfs.Obfuscate(p)
	return c.PacketConn.WriteTo(obfs, addr)
}
