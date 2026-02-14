package auth

import (
	"sync"

	"github.com/smartlink/slp-server/internal/config"
)

type Manager struct {
	tokens map[string]*TokenInfo
	mu     sync.RWMutex
}

type TokenInfo struct {
	Name       string
	Bandwidth  int    // Mbps, 0=unlimited
	OutboundIP string // 出口 IP，空=默认
}

func NewManager(cfg *config.AuthConfig) *Manager {
	m := &Manager{
		tokens: make(map[string]*TokenInfo),
	}

	for _, t := range cfg.Tokens {
		m.tokens[t.Token] = &TokenInfo{
			Name:       t.Name,
			Bandwidth:  t.Bandwidth,
			OutboundIP: t.OutboundIP,
		}
	}

	return m
}

// Verify 验证 token，返回 token 信息
func (m *Manager) Verify(token string) (*TokenInfo, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	info, ok := m.tokens[token]
	return info, ok
}

// AddToken 动态添加 token
func (m *Manager) AddToken(token string, info *TokenInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[token] = info
}

// RemoveToken 移除 token
func (m *Manager) RemoveToken(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tokens, token)
}
