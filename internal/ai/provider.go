package ai

import (
	"context"

	"aegis-phishing/internal/model"
)

// AIProvider defines the interface for threat analysis backends.
// Implementations include DeepSeek, and can be extended for Gemini, OpenAI, etc.
type AIProvider interface {
	// Analyze performs threat classification on the given URL and its extracted features.
	Analyze(ctx context.Context, url string, features *model.PageFeatures) (*model.AIAnalysis, error)

	// Name returns the provider identifier.
	Name() string
}
