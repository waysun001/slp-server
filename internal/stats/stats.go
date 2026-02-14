package stats

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type Stats struct {
	mu          sync.RWMutex
	connections int64
	totalIn     int64
	totalOut    int64
	clients     map[string]*ClientStats
	startTime   time.Time
}

type ClientStats struct {
	Name        string    `json:"name"`
	Connections int64     `json:"connections"`
	BytesIn     int64     `json:"bytes_in"`
	BytesOut    int64     `json:"bytes_out"`
	LastSeen    time.Time `json:"last_seen"`
}

type StatsResponse struct {
	Uptime      string                  `json:"uptime"`
	Connections int64                   `json:"connections"`
	TotalIn     int64                   `json:"total_in"`
	TotalOut    int64                   `json:"total_out"`
	Clients     map[string]*ClientStats `json:"clients"`
}

var globalStats *Stats

func init() {
	globalStats = &Stats{
		clients:   make(map[string]*ClientStats),
		startTime: time.Now(),
	}
}

// AddConnection 增加连接计数
func AddConnection(clientName string) {
	atomic.AddInt64(&globalStats.connections, 1)
	
	globalStats.mu.Lock()
	defer globalStats.mu.Unlock()
	
	if _, ok := globalStats.clients[clientName]; !ok {
		globalStats.clients[clientName] = &ClientStats{Name: clientName}
	}
	globalStats.clients[clientName].Connections++
	globalStats.clients[clientName].LastSeen = time.Now()
}

// RemoveConnection 减少连接计数
func RemoveConnection(clientName string) {
	atomic.AddInt64(&globalStats.connections, -1)
}

// AddBytes 增加流量计数
func AddBytes(clientName string, in, out int64) {
	atomic.AddInt64(&globalStats.totalIn, in)
	atomic.AddInt64(&globalStats.totalOut, out)
	
	globalStats.mu.Lock()
	defer globalStats.mu.Unlock()
	
	if client, ok := globalStats.clients[clientName]; ok {
		atomic.AddInt64(&client.BytesIn, in)
		atomic.AddInt64(&client.BytesOut, out)
	}
}

// GetStats 获取统计信息
func GetStats() *StatsResponse {
	globalStats.mu.RLock()
	defer globalStats.mu.RUnlock()
	
	clients := make(map[string]*ClientStats)
	for k, v := range globalStats.clients {
		clients[k] = &ClientStats{
			Name:        v.Name,
			Connections: v.Connections,
			BytesIn:     atomic.LoadInt64(&v.BytesIn),
			BytesOut:    atomic.LoadInt64(&v.BytesOut),
			LastSeen:    v.LastSeen,
		}
	}
	
	return &StatsResponse{
		Uptime:      time.Since(globalStats.startTime).String(),
		Connections: atomic.LoadInt64(&globalStats.connections),
		TotalIn:     atomic.LoadInt64(&globalStats.totalIn),
		TotalOut:    atomic.LoadInt64(&globalStats.totalOut),
		Clients:     clients,
	}
}

// StartAPI 启动统计 API 服务
func StartAPI(addr string) {
	mux := http.NewServeMux()
	
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(GetStats())
	})
	
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	
	log.Printf("Stats API listening on %s", addr)
	
	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Printf("Stats API error: %v", err)
		}
	}()
}
