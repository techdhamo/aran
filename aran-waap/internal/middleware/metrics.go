// Copyright 2024-2026 Mazhai Technologies
// Licensed under the Apache License, Version 2.0

package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// RequestCounter tracks total requests
	requestCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aran_waap_requests_total",
			Help: "Total number of requests processed",
		},
		[]string{"method", "endpoint", "status"},
	)

	// RequestDuration tracks request latency
	requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "aran_waap_request_duration_seconds",
			Help:    "Request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint"},
	)

	// ThreatCounter tracks detected threats
	threatCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aran_waap_threats_detected_total",
			Help: "Total number of threats detected",
		},
		[]string{"threat_type"},
	)

	// ActiveConnections tracks current connections
	activeConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "aran_waap_active_connections",
			Help: "Number of active connections",
		},
	)
)

func init() {
	prometheus.MustRegister(requestCounter)
	prometheus.MustRegister(requestDuration)
	prometheus.MustRegister(threatCounter)
	prometheus.MustRegister(activeConnections)
}

// MetricsHandler returns Prometheus metrics endpoint
func MetricsHandler() gin.HandlerFunc {
	handler := promhttp.Handler()
	return func(c *gin.Context) {
		handler.ServeHTTP(c.Writer, c.Request)
	}
}

// RecordRequest records metrics for a request
func RecordRequest(method, endpoint string, status int) {
	requestCounter.WithLabelValues(method, endpoint, string(rune(status))).Inc()
}

// RecordThreat records a detected threat
func RecordThreat(threatType string) {
	threatCounter.WithLabelValues(threatType).Inc()
}
