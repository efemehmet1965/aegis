package handler

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"aegis-phishing/internal/ai"
	"aegis-phishing/internal/analyzer"
	"aegis-phishing/internal/fetcher"
	"aegis-phishing/internal/model"
	"aegis-phishing/internal/parser"
	"aegis-phishing/pkg"
)

// CheckHandler performs single-URL threat analysis.
type CheckHandler struct {
	fetcher      *fetcher.Fetcher
	whoisFetcher *fetcher.WhoisFetcher
	parser       *parser.Parser
	preAnalyzer  *analyzer.PreAnalyzer
	ai           ai.AIProvider
}

// NewCheckHandler creates a new check handler with all required dependencies.
func NewCheckHandler(f *fetcher.Fetcher, wf *fetcher.WhoisFetcher, p *parser.Parser,
	pre *analyzer.PreAnalyzer, aiProvider ai.AIProvider) *CheckHandler {
	return &CheckHandler{
		fetcher:      f,
		whoisFetcher: wf,
		parser:       p,
		preAnalyzer:  pre,
		ai:           aiProvider,
	}
}

// Handle processes a single URL threat check.
// POST /api/v1/check
func (h *CheckHandler) Handle(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	var req model.CheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request format", err.Error())
		return
	}

	if req.URL == "" {
		writeError(w, http.StatusBadRequest, "URL field is required", "")
		return
	}

	normalizedURL, err := utils.NormalizeURL(req.URL)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid URL", err.Error())
		return
	}

	domain := utils.ExtractDomain(normalizedURL)
	slog.Info("check started", "url", normalizedURL, "domain", domain)

	// Phase 1: WHOIS lookup (independent of page fetch)
	whoisInfo := h.whoisFetcher.Lookup(r.Context(), domain)

	// Phase 2: Fetch page content and SSL info
	fetchResult, fetchErr := h.fetcher.Fetch(r.Context(), normalizedURL)
	if fetchErr != nil && fetchResult == nil {
		fetchResult = &fetcher.FetchResult{
			FinalURL: normalizedURL,
		}
	}
	finalURL := normalizedURL
	if fetchResult.FinalURL != "" {
		finalURL = fetchResult.FinalURL
	}

	if fetchErr != nil {
		slog.Warn("fetch partially failed, continuing with URL+domain analysis",
			"url", normalizedURL, "error", fetchErr)
	}

	// Phase 3: Extract features from HTML and URL structure
	pageFeatures := h.parser.Extract(fetchResult.HTML, finalURL, fetchResult.SSLInfo)
	pageFeatures.WhoisInfo = whoisInfo

	// Phase 4: Multi-layer heuristic pre-scoring
	preResult := h.preAnalyzer.Analyze(domain, pageFeatures, whoisInfo)
	slog.Info("pre-analysis complete",
		"url", normalizedURL,
		"score", preResult.TotalScore,
		"recommendation", preResult.Recommendation,
		"flag_count", len(preResult.Flags),
	)

	// Phase 5: AI classification with extended timeout
	aiCtx, aiCancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer aiCancel()

	analysis, aiErr := h.ai.Analyze(aiCtx, finalURL, pageFeatures)

	// Phase 5b: Fallback to heuristic result when AI fails
	if aiErr != nil {
		slog.Error("AI analysis failed, falling back to pre-analysis",
			"url", normalizedURL, "error", aiErr)

		label := "safe"
		category := "safe"
		if preResult.IsSuspicious {
			label = "generic_phishing"
			category = "phishing"
		}
		analysis = &model.AIAnalysis{
			IsThreat:   preResult.IsSuspicious,
			Label:      label,
			Category:   category,
			Confidence: float64(preResult.TotalScore) / 100.0,
			RiskLevel:  riskFromScore(preResult.TotalScore),
			Reasons:    preResult.Flags,
			Indicators: preResult.Flags,
		}
	}

	// Phase 5c: Pre-analyzer override for high-confidence heuristic results.
	// When the pre-analyzer score exceeds 35 and AI classifies as safe,
	// the heuristic verdict takes precedence.
	if preResult.TotalScore >= 35 && !analysis.IsThreat {
		slog.Warn("pre-analyzer override: AI classified safe but heuristics indicate threat",
			"url", normalizedURL, "pre_score", preResult.TotalScore)
		analysis.IsThreat = true
		analysis.Label = "generic_phishing"
		analysis.Category = "phishing"
		analysis.Confidence = float64(preResult.TotalScore) / 100.0
		if analysis.Confidence < 0.75 {
			analysis.Confidence = 0.75
		}
		analysis.RiskLevel = riskFromScore(preResult.TotalScore)
		analysis.Reasons = append([]string{
			"Pre-analysis heuristics detected threat indicators in domain structure and metadata.",
		}, analysis.Reasons...)
	}

	// Free hosting subdomains have misleading WHOIS ages (the base domain, not
	// the subdomain). When free hosting is detected with sufficient risk score,
	// override the AI classification.
	if whoisInfo.IsFreeHosting && preResult.TotalScore >= 35 && !analysis.IsThreat {
		slog.Warn("free hosting override: WHOIS age belongs to base domain, not subdomain",
			"url", normalizedURL, "pre_score", preResult.TotalScore)
		analysis.IsThreat = true
		analysis.Label = "generic_phishing"
		analysis.Category = "phishing"
		analysis.Confidence = 0.80
		analysis.RiskLevel = "high"
		analysis.Reasons = append([]string{
			"Free hosting subdomain — commonly used in phishing campaigns. WHOIS age reflects the base domain, not this subdomain.",
		}, analysis.Reasons...)
	}

	// Phase 6: Assemble response
	response := model.CheckResponse{
		URL:         finalURL,
		IsThreat:    analysis.IsThreat,
		Label:       analysis.Label,
		Category:    analysis.Category,
		Confidence:  analysis.Confidence,
		Analysis:    analysis,
		Features:    pageFeatures,
		SSLInfo:     fetchResult.SSLInfo,
		PreAnalysis: preResult,
	}

	if fetchErr != nil {
		response.FetchError = fetchErr.Error()
	}

	slog.Info("check completed",
		"url", normalizedURL,
		"is_threat", analysis.IsThreat,
		"label", analysis.Label,
		"category", analysis.Category,
		"confidence", analysis.Confidence,
		"risk_level", analysis.RiskLevel,
		"pre_score", preResult.TotalScore,
		"domain_age_days", whoisInfo.DomainAgeDays,
		"duration_ms", time.Since(start).Milliseconds(),
	)

	writeJSON(w, http.StatusOK, response)
}

func riskFromScore(score int) string {
	switch {
	case score >= 60:
		return "high"
	case score >= 30:
		return "medium"
	case score >= 15:
		return "low"
	default:
		return "safe"
	}
}
