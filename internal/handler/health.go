package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"aegis-phishing/internal/model"
)

var startTime = time.Now()

// HealthHandler provides a health check endpoint.
type HealthHandler struct{}

// NewHealthHandler creates a new health check handler.
func NewHealthHandler() *HealthHandler {
	return &HealthHandler{}
}

// Handle responds with server status, version, and uptime.
// GET /api/v1/health
func (h *HealthHandler) Handle(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, model.HealthResponse{
		Status:  "ok",
		Version: "1.0.0",
		Uptime:  time.Since(startTime).Round(time.Second).String(),
	})
}

// Shared response helpers used across handler packages.

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message, details string) {
	writeJSON(w, status, model.ErrorResponse{
		Error:   message,
		Code:    status,
		Details: details,
	})
}
