package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/smartlink/slp-server/internal/config"
	"github.com/smartlink/slp-server/internal/server"
	"github.com/smartlink/slp-server/internal/stats"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
)

func main() {
	configPath := flag.String("c", "/etc/slp/config.yaml", "config file path")
	showVersion := flag.Bool("v", false, "show version")
	flag.Parse()

	if *showVersion {
		log.Printf("SLP Server %s (built %s)", Version, BuildTime)
		return
	}

	// 加载配置
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 启动统计 API
	if cfg.Stats.Enabled && cfg.Stats.APIAddr != "" {
		stats.StartAPI(cfg.Stats.APIAddr)
	}

	// 创建服务器
	srv, err := server.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// 启动服务器
	if err := srv.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	log.Printf("SLP Server [%s] started (version %s)", cfg.Server.Name, Version)

	// 等待退出信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down...")
	srv.Stop()
}
