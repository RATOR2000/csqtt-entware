// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/RATOR2000/csqtt-entware/internal/manager"
)

var version = "development"

func main() {
	runtime.GOMAXPROCS(1)
	debug.SetMemoryLimit(16 << 20)
	debug.SetGCPercent(75)
	opts := manager.Options{}
	flag.StringVar(&opts.Listen, "listen", "192.168.2.1:8080", "Exact LAN IPv4 and port")
	flag.StringVar(&opts.ConfigPath, "config", "/opt/etc/csqtt/settings.json", "Private settings path")
	flag.StringVar(&opts.RuntimeDir, "runtime", "/tmp/csqtt", "Private tmpfs runtime directory")
	flag.StringVar(&opts.CorePath, "core", "/opt/bin/csqtt-client", "CSQTT core binary")
	showVersion := flag.Bool("version", false, "Print build version")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	m, err := manager.New(opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "CSQTT manager initialization failed:", err)
		os.Exit(1)
	}
	listener, err := net.Listen("tcp4", opts.Listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "CSQTT panel address unavailable")
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	server := &http.Server{Handler: m.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	go m.Run(ctx)
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	fmt.Println("CSQTT Entware", version, "panel listening on", opts.Listen)
	if err = server.Serve(listener); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "CSQTT panel stopped unexpectedly")
	}
	m.Close()
}
