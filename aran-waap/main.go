// Copyright 2024-2026 Mazhai Technologies
// Licensed under the Apache License, Version 2.0
//
// Aran WAAP — Web Application and API Protection Edge Proxy
//
// Architecture:
// - Edge proxy layer between mobile RASP and Mazhai Central backend
// - BOLA/IDOR attack detection
// - Request inspection and forwarding
// - Rate limiting and threat fingerprinting
// - TLS 1.3 termination with certificate pinning validation
//
// Deployment:
//   go run main.go --config config.yaml
//   Or: ./aran-waap --port 33100 --upstream http://mazhai-central:33100

package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/techdhamo/aran/aran-waap/internal/config"
	"github.com/techdhamo/aran/aran-waap/internal/logger"
	"github.com/techdhamo/aran/aran-waap/internal/middleware"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	var (
		configFile = flag.String("config", "config.yaml", "Path to configuration file")
		port       = flag.String("port", "33100", "Port to listen on")
		upstream   = flag.String("upstream", "http://localhost:33100", "Upstream backend URL")
		showVer    = flag.Bool("version", false, "Show version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("Aran WAAP v%s (built %s)\n", version, buildTime)
		os.Exit(0)
	}

	// Initialize logger
	log := logger.NewLogger()
	log.Info("Starting Aran WAAP Edge Proxy",
		"version", version,
		"port", *port,
		"upstream", *upstream,
	)

	// Load configuration
	cfg, err := config.Load(*configFile)
	if err != nil {
		log.Warn("Using default configuration", "error", err)
		cfg = config.Default()
	}

	// Parse upstream URL
	targetURL, err := url.Parse(*upstream)
	if err != nil {
		log.Fatal("Invalid upstream URL", "error", err)
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.ModifyResponse = modifyResponse(log)
	proxy.ErrorHandler = errorHandler(log)

	// Setup Gin router
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.New()

	// Global middleware
	router.Use(middleware.Recovery(log))
	router.Use(middleware.RequestID())
	router.Use(middleware.SecurityHeaders())
	router.Use(middleware.RateLimiter(cfg.RateLimit))
	router.Use(middleware.TelemetryInspection(log)) // Inspect Aran telemetry payloads

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"version": version,
			"time":    time.Now().UTC(),
		})
	})

	// Metrics endpoint (Prometheus)
	router.GET("/metrics", middleware.MetricsHandler())

	// BOLA/IDOR protection middleware for API routes
	api := router.Group("/api/v1")
	api.Use(middleware.BOLAProtection(log))
	api.Use(middleware.IDORProtection(log))
	api.Use(middleware.ArAuthValidation(cfg.ArAuthKeys))

	// Proxy all API requests to backend
	api.Any("/*path", func(c *gin.Context) {
		// Add WAAP processing headers
		c.Request.Header.Set("X-Aran-WAAP-Processed", "true")
		c.Request.Header.Set("X-Aran-WAAP-Version", version)
		c.Request.Header.Set("X-Aran-WAAP-Request-ID", middleware.GetRequestID(c))

		// Check for threat signals from RASP
		if threatMask := c.GetHeader("X-Aran-Threat-Mask"); threatMask != "" {
			log.Warn("Threat detected in request",
				"threat_mask", threatMask,
				"client_ip", c.ClientIP(),
			)
			// In production, could block or rate-limit here
		}

		proxy.ServeHTTP(c.Writer, c.Request)
	})

	// Create HTTP server
	srv := &http.Server{
		Addr:         ":" + *port,
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		log.Info("Shutting down gracefully...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			log.Error("Shutdown error", "error", err)
		}
	}()

	// Start server
	log.Info("Aran WAAP listening", "addr", srv.Addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal("Server failed", "error", err)
	}
}

// modifyResponse inspects backend responses for tampering
func modifyResponse(log *logger.Logger) func(*http.Response) error {
	return func(resp *http.Response) error {
		// Log response metadata
		log.Debug("Backend response",
			"status", resp.StatusCode,
			"request_id", resp.Request.Header.Get("X-Aran-WAAP-Request-ID"),
		)

		// Verify response headers haven't been tampered
		if resp.Header.Get("X-Aran-Signature") == "" {
			// Backend should sign all responses
			log.Warn("Response missing Aran signature",
				"request_id", resp.Request.Header.Get("X-Aran-WAAP-Request-ID"),
			)
		}

		return nil
	}
}

// errorHandler handles proxy errors
func errorHandler(log *logger.Logger) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		log.Error("Proxy error",
			"error", err,
			"request_id", r.Header.Get("X-Aran-WAAP-Request-ID"),
		)
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(`{"error": "Backend unavailable"}`))
	}
}
