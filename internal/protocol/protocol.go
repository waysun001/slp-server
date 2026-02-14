package protocol

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

const (
	Version = 0x01

	// Auth types
	AuthToken = 0x01

	// Frame types
	FrameTCP       = 0x01
	FrameUDP       = 0x02
	FrameHeartbeat = 0xFE
	FrameClose     = 0xFF

	// Address types
	AddrIPv4   = 0x01
	AddrIPv6   = 0x04
	AddrDomain = 0x03
)

var (
	ErrInvalidVersion  = errors.New("invalid protocol version")
	ErrInvalidAuthType = errors.New("invalid auth type")
	ErrAuthFailed      = errors.New("authentication failed")
)

// AuthFrame 认证帧
type AuthFrame struct {
	Version  byte
	AuthType byte
	Token    string
}

// ReadAuthFrame 从连接读取认证帧
func ReadAuthFrame(r io.Reader) (*AuthFrame, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	if header[0] != Version {
		return nil, ErrInvalidVersion
	}

	if header[1] != AuthToken {
		return nil, ErrInvalidAuthType
	}

	tokenLen := binary.BigEndian.Uint16(header[2:4])
	token := make([]byte, tokenLen)
	if _, err := io.ReadFull(r, token); err != nil {
		return nil, err
	}

	return &AuthFrame{
		Version:  header[0],
		AuthType: header[1],
		Token:    string(token),
	}, nil
}

// WriteAuthFrame 写入认证帧
func WriteAuthFrame(w io.Writer, token string) error {
	tokenBytes := []byte(token)
	frame := make([]byte, 4+len(tokenBytes))
	frame[0] = Version
	frame[1] = AuthToken
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(tokenBytes)))
	copy(frame[4:], tokenBytes)
	_, err := w.Write(frame)
	return err
}

// AuthResponse 认证响应
func WriteAuthResponse(w io.Writer, success bool) error {
	resp := []byte{Version, 0x00}
	if success {
		resp[1] = 0x01
	}
	_, err := w.Write(resp)
	return err
}

// DataFrame 数据帧
type DataFrame struct {
	Type     byte
	AddrType byte
	Addr     string
	Port     uint16
	Payload  []byte
}

// ReadDataFrame 读取数据帧
func ReadDataFrame(r io.Reader) (*DataFrame, error) {
	header := make([]byte, 3)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	frame := &DataFrame{
		Type:     header[0],
		AddrType: header[1],
	}

	// 心跳或关闭帧
	if frame.Type == FrameHeartbeat || frame.Type == FrameClose {
		return frame, nil
	}

	addrLen := int(header[2])
	addrBytes := make([]byte, addrLen)
	if _, err := io.ReadFull(r, addrBytes); err != nil {
		return nil, err
	}

	switch frame.AddrType {
	case AddrIPv4:
		frame.Addr = net.IP(addrBytes).String()
	case AddrIPv6:
		frame.Addr = net.IP(addrBytes).String()
	case AddrDomain:
		frame.Addr = string(addrBytes)
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(r, portBytes); err != nil {
		return nil, err
	}
	frame.Port = binary.BigEndian.Uint16(portBytes)

	// 读取 payload 长度
	payloadLenBytes := make([]byte, 4)
	if _, err := io.ReadFull(r, payloadLenBytes); err != nil {
		return nil, err
	}
	payloadLen := binary.BigEndian.Uint32(payloadLenBytes)

	if payloadLen > 0 {
		frame.Payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, frame.Payload); err != nil {
			return nil, err
		}
	}

	return frame, nil
}

// WriteDataFrame 写入数据帧
func WriteDataFrame(w io.Writer, frame *DataFrame) error {
	var addrBytes []byte
	switch frame.AddrType {
	case AddrIPv4:
		addrBytes = net.ParseIP(frame.Addr).To4()
	case AddrIPv6:
		addrBytes = net.ParseIP(frame.Addr).To16()
	case AddrDomain:
		addrBytes = []byte(frame.Addr)
	}

	buf := make([]byte, 3+len(addrBytes)+2+4+len(frame.Payload))
	buf[0] = frame.Type
	buf[1] = frame.AddrType
	buf[2] = byte(len(addrBytes))
	copy(buf[3:], addrBytes)
	binary.BigEndian.PutUint16(buf[3+len(addrBytes):], frame.Port)
	binary.BigEndian.PutUint32(buf[3+len(addrBytes)+2:], uint32(len(frame.Payload)))
	copy(buf[3+len(addrBytes)+6:], frame.Payload)

	_, err := w.Write(buf)
	return err
}

// WriteHeartbeat 写入心跳帧
func WriteHeartbeat(w io.Writer) error {
	_, err := w.Write([]byte{FrameHeartbeat, 0x00, 0x00})
	return err
}
