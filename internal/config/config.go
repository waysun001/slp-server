package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server  ServerConfig  `yaml:"server"`
	Listen  ListenConfig  `yaml:"listen"`
	TLS     TLSConfig     `yaml:"tls"`
	Auth    AuthConfig    `yaml:"auth"`
	Log     LogConfig     `yaml:"log"`
	Stats   StatsConfig   `yaml:"stats"`
}

type ServerConfig struct {
	Name string `yaml:"name"`
}

type ListenConfig struct {
	QUIC      QUICConfig      `yaml:"quic"`
	WebSocket WebSocketConfig `yaml:"websocket"`
	KCP       KCPConfig       `yaml:"kcp"`
}

type QUICConfig struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
}

type WebSocketConfig struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
	Path    string `yaml:"path"`
}

type KCPConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Addr      string `yaml:"addr"`
	FECData   int    `yaml:"fec_data"`
	FECParity int    `yaml:"fec_parity"`
}

type TLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
	SNI  string `yaml:"sni"`
}

type AuthConfig struct {
	Tokens []TokenConfig `yaml:"tokens"`
}

type TokenConfig struct {
	Name      string `yaml:"name"`
	Token     string `yaml:"token"`
	Bandwidth int    `yaml:"bandwidth"` // Mbps, 0=unlimited
}

type LogConfig struct {
	Level string `yaml:"level"`
	File  string `yaml:"file"`
}

type StatsConfig struct {
	Enabled bool   `yaml:"enabled"`
	APIAddr string `yaml:"api_addr"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// 设置默认值
	if cfg.Listen.QUIC.Addr == "" {
		cfg.Listen.QUIC.Addr = ":443"
	}
	if cfg.Listen.WebSocket.Path == "" {
		cfg.Listen.WebSocket.Path = "/ws"
	}
	if cfg.Log.Level == "" {
		cfg.Log.Level = "info"
	}

	return &cfg, nil
}
