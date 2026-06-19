package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds all application configuration loaded from environment variables.
type Config struct {
	// Server
	Port     string
	LogLevel string

	// DeepSeek AI
	DeepSeekAPIKey  string
	DeepSeekModel   string
	DeepSeekBaseURL string

	// HTTP Fetcher
	FetchTimeout time.Duration
	MaxBodySize  int64
	UserAgent    string

	// Reverse IP Lookup
	ViewDNSAPIKey       string
	HackerTargetBaseURL string

	// Sweep mode
	MaxSiblingScans  int
	SweepConcurrency int
}

// Load reads configuration from environment variables with sensible defaults.
func Load() *Config {
	return &Config{
		Port:     getEnv("PORT", "8080"),
		LogLevel: getEnv("LOG_LEVEL", "info"),

		DeepSeekAPIKey:  getEnv("DEEPSEEK_API_KEY", ""),
		DeepSeekModel:   getEnv("DEEPSEEK_MODEL", "deepseek-chat"),
		DeepSeekBaseURL: getEnv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1"),

		FetchTimeout: time.Duration(getEnvInt("FETCH_TIMEOUT_SEC", 15)) * time.Second,
		MaxBodySize:  int64(getEnvInt("MAX_BODY_SIZE_MB", 5)) * 1024 * 1024,
		UserAgent:    getEnv("USER_AGENT", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"),

		ViewDNSAPIKey:       getEnv("VIEWDNS_API_KEY", ""),
		HackerTargetBaseURL: getEnv("HACKERTARGET_BASE_URL", "https://api.hackertarget.com/reverseiplookup"),

		MaxSiblingScans:  getEnvInt("MAX_SIBLING_SCANS", 20),
		SweepConcurrency: getEnvInt("SWEEP_CONCURRENCY", 5),
	}
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return defaultVal
}
