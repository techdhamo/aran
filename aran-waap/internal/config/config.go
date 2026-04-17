// Copyright 2024-2026 Mazhai Technologies
// Licensed under the Apache License, Version 2.0

package config

import (
	"github.com/spf13/viper"
)

// Config holds WAAP configuration
type Config struct {
	Environment string         `mapstructure:"environment"`
	Port        int            `mapstructure:"port"`
	Upstream    string         `mapstructure:"upstream"`
	RateLimit   RateLimitConfig `mapstructure:"rate_limit"`
	ArAuthKeys  []string       `mapstructure:"ar_auth_keys"`
	TLS         TLSConfig      `mapstructure:"tls"`
}

// RateLimitConfig defines rate limiting parameters
type RateLimitConfig struct {
	RequestsPerSecond float64 `mapstructure:"requests_per_second"`
	BurstSize         int     `mapstructure:"burst_size"`
	BlockDuration     int     `mapstructure:"block_duration_minutes"`
}

// TLSConfig defines TLS settings
type TLSConfig struct {
	Enabled     bool   `mapstructure:"enabled"`
	CertFile    string `mapstructure:"cert_file"`
	KeyFile     string `mapstructure:"key_file"`
	MinVersion  string `mapstructure:"min_version"`
	CipherSuites []string `mapstructure:"cipher_suites"`
}

// Default returns default configuration
func Default() *Config {
	return &Config{
		Environment: "production",
		Port:        33100,
		Upstream:    "http://localhost:33100",
		RateLimit: RateLimitConfig{
			RequestsPerSecond: 1000.0,
			BurstSize:         1500,
			BlockDuration:     10,
		},
		ArAuthKeys: []string{},
		TLS: TLSConfig{
			Enabled:     true,
			MinVersion:  "1.3",
			CipherSuites: []string{"TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"},
		},
	}
}

// Load reads configuration from file
func Load(path string) (*Config, error) {
	viper.SetConfigFile(path)
	viper.SetConfigType("yaml")

	// Environment variable overrides
	viper.SetEnvPrefix("ARAN_WAAP")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
