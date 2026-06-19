package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"aegis-phishing/config"
	"aegis-phishing/internal/ai"
	"aegis-phishing/internal/analyzer"
	"aegis-phishing/internal/fetcher"
	"aegis-phishing/internal/model"
	"aegis-phishing/internal/parser"
	"aegis-phishing/pkg"

	"github.com/go-chi/chi/v5"
)

type sweepTask struct {
	ID        string               `json:"id"`
	Status    string               `json:"status"`
	Progress  int                  `json:"progress"`
	Result    *model.SweepResponse `json:"result,omitempty"`
	Error     string               `json:"error,omitempty"`
	CreatedAt time.Time            `json:"created_at"`
	UpdatedAt time.Time            `json:"updated_at"`
}

// SweepHandler manages async reverse IP + sibling domain scanning.
type SweepHandler struct {
	cfg          *config.Config
	fetcher      *fetcher.Fetcher
	reverseIP    *fetcher.ReverseIPFetcher
	whoisFetcher *fetcher.WhoisFetcher
	parser       *parser.Parser
	preAnalyzer  *analyzer.PreAnalyzer
	ai           ai.AIProvider

	mu    sync.RWMutex
	tasks map[string]*sweepTask
}

func NewSweepHandler(cfg *config.Config, f *fetcher.Fetcher,
	rip *fetcher.ReverseIPFetcher, wf *fetcher.WhoisFetcher,
	p *parser.Parser, pre *analyzer.PreAnalyzer, aiProvider ai.AIProvider) *SweepHandler {
	return &SweepHandler{
		cfg:          cfg,
		fetcher:      f,
		reverseIP:    rip,
		whoisFetcher: wf,
		parser:       p,
		preAnalyzer:  pre,
		ai:           aiProvider,
		tasks:        make(map[string]*sweepTask),
	}
}

// StartSweep creates an async sweep task and returns immediately.
// POST /api/v1/sweep
func (h *SweepHandler) StartSweep(w http.ResponseWriter, r *http.Request) {
	var req model.SweepRequest
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

	taskID := fmt.Sprintf("sweep_%d", time.Now().UnixNano())
	task := &sweepTask{
		ID:        taskID,
		Status:    "pending",
		Progress:  0,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	h.mu.Lock()
	h.tasks[taskID] = task
	h.mu.Unlock()

	go h.runFullSweep(task, normalizedURL, req.ScanSiblings)

	slog.Info("sweep task created", "task_id", taskID, "url", normalizedURL)

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"task_id":   taskID,
		"status":    "pending",
		"url":       normalizedURL,
		"check_url": fmt.Sprintf("/api/v1/sweep/%s", taskID),
	})
}

// GetTaskStatus returns the current state or final result of a sweep task.
// GET /api/v1/sweep/{taskID}
func (h *SweepHandler) GetTaskStatus(w http.ResponseWriter, r *http.Request) {
	taskID := chi.URLParam(r, "taskID")

	h.mu.RLock()
	task, ok := h.tasks[taskID]
	h.mu.RUnlock()

	if !ok {
		writeError(w, http.StatusNotFound, "Task not found", taskID)
		return
	}

	if task.Status == "done" && task.Result != nil {
		writeJSON(w, http.StatusOK, task.Result)
		return
	}

	if task.Status == "failed" {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"task_id": task.ID,
			"status":  "failed",
			"error":   task.Error,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"task_id":    task.ID,
		"status":     task.Status,
		"progress":   task.Progress,
		"created_at": task.CreatedAt,
		"updated_at": task.UpdatedAt,
	})
}

// runFullSweep executes the complete sweep pipeline in the background.
func (h *SweepHandler) runFullSweep(task *sweepTask, url string, scanSiblings bool) {
	h.updateTask(task, "running", 5)

	// Step 1: Fast heuristic scan of original URL (no AI, ~3-5s)
	ctx := context.Background()

	fetchResult, err := h.fetcher.Fetch(ctx, url)
	if err != nil {
		h.updateTaskError(task, "Failed to fetch original URL: "+err.Error())
		return
	}

	domain := utils.ExtractDomain(fetchResult.FinalURL)
	whoisInfo := h.whoisFetcher.Lookup(ctx, domain)
	pageFeatures := h.parser.Extract(fetchResult.HTML, fetchResult.FinalURL, fetchResult.SSLInfo)
	pageFeatures.WhoisInfo = whoisInfo
	preResult := h.preAnalyzer.Analyze(domain, pageFeatures, whoisInfo)

	isThreat := preResult.Recommendation == "likely_phishing" || preResult.TotalScore >= 35
	label := "safe"
	category := "safe"
	if isThreat {
		label = "generic_phishing"
		category = "phishing"
	}
	conf := float64(preResult.TotalScore) / 100.0
	if conf > 0.95 {
		conf = 0.95
	}

	task.Result = &model.SweepResponse{
		Original: model.CheckResponse{
			URL:         fetchResult.FinalURL,
			IsThreat:    isThreat,
			Label:       label,
			Category:    category,
			Confidence:  conf,
			Analysis: &model.AIAnalysis{
				IsThreat:   isThreat,
				Label:      label,
				Category:   category,
				Confidence: conf,
				RiskLevel:  riskFromScore(preResult.TotalScore),
				Reasons:    preResult.Flags,
				Indicators: preResult.Flags,
			},
			Features:    pageFeatures,
			SSLInfo:     fetchResult.SSLInfo,
			PreAnalysis: preResult,
		},
	}

	h.updateTask(task, "running", 20)

	if !scanSiblings {
		task.Result.Summary = &model.SweepSummary{}
		h.updateTask(task, "done", 100)
		return
	}

	// Step 2: Reverse IP lookup (20-30%)
	reverseResult, err := h.reverseIP.Lookup(ctx, domain)
	if err != nil {
		slog.Warn("reverse IP failed, finishing with original only", "domain", domain, "error", err)
		task.Result.Summary = &model.SweepSummary{}
		h.updateTask(task, "done", 100)
		return
	}

	task.Result.IP = reverseResult.IP
	task.Result.ReverseIP = reverseResult

	// Step 3: Background sibling scanning (30-100%)
	domainsToScan := reverseResult.DomainsFound
	if len(domainsToScan) > h.cfg.MaxSiblingScans {
		domainsToScan = domainsToScan[:h.cfg.MaxSiblingScans]
	}

	h.updateTask(task, "running", 30)

	concurrency := h.cfg.SweepConcurrency
	if concurrency < 1 {
		concurrency = 10
	}

	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup
	total := len(domainsToScan)
	completed := 0

	summary := &model.SweepSummary{TotalScanned: total}
	var siblingResults []model.CheckResponse

	for _, d := range domainsToScan {
		if d == domain {
			summary.SkippedCount++
			completed++
			continue
		}

		wg.Add(1)
		go func(dom string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result := h.quickScanDomain(dom)
			mu.Lock()
			if result != nil {
				siblingResults = append(siblingResults, *result)
				if result.IsThreat {
					summary.PhishingDetected++
				}
			} else {
				summary.ErrorCount++
			}
			completed++
			progress := 30 + (completed*70)/total
			h.updateTask(task, "running", progress)
			mu.Unlock()
		}(d)
	}

	wg.Wait()

	if summary.TotalScanned > 0 {
		summary.PhishingRatio = float64(summary.PhishingDetected) / float64(summary.TotalScanned)
	}
	summary.LikelyBulletproofHosting = summary.PhishingRatio >= 0.5 && summary.TotalScanned >= 5

	task.Result.SiblingResults = siblingResults
	task.Result.Summary = summary

	slog.Info("background sweep completed",
		"task_id", task.ID,
		"ip", reverseResult.IP,
		"total", total,
		"phishing", summary.PhishingDetected,
		"ratio", fmt.Sprintf("%.2f", summary.PhishingRatio),
	)

	h.updateTask(task, "done", 100)
}

func (h *SweepHandler) quickScanDomain(domain string) *model.CheckResponse {
	ctx := context.Background()
	siblingURL := "https://" + domain

	whoisInfo := h.whoisFetcher.Lookup(ctx, domain)

	fetchResult, err := h.fetcher.Fetch(ctx, siblingURL)
	if err != nil {
		siblingURLHTTP := "http://" + domain
		fetchResult, err = h.fetcher.Fetch(ctx, siblingURLHTTP)
		if err != nil {
			fetchResult = &fetcher.FetchResult{
				FinalURL:   siblingURL,
				FetchError: err.Error(),
			}
		}
	}

	finalURL := fetchResult.FinalURL
	if finalURL == "" {
		finalURL = siblingURL
	}

	pageFeatures := h.parser.Extract(fetchResult.HTML, finalURL, fetchResult.SSLInfo)
	pageFeatures.WhoisInfo = whoisInfo

	preResult := h.preAnalyzer.Analyze(domain, pageFeatures, whoisInfo)

	isThreat := preResult.Recommendation == "likely_phishing" || preResult.TotalScore >= 35
	label := "safe"
	category := "safe"
	if isThreat {
		label = "generic_phishing"
		category = "phishing"
	}

	confidence := float64(preResult.TotalScore) / 100.0
	if confidence > 0.95 {
		confidence = 0.95
	}

	return &model.CheckResponse{
		URL:        finalURL,
		IsThreat:   isThreat,
		Label:      label,
		Category:   category,
		Confidence: confidence,
		Analysis: &model.AIAnalysis{
			IsThreat:   isThreat,
			Label:      label,
			Category:   category,
			Confidence: confidence,
			RiskLevel:  riskFromScore(preResult.TotalScore),
			Reasons:    preResult.Flags,
			Indicators: preResult.Flags,
		},
		Features:    pageFeatures,
		SSLInfo:     fetchResult.SSLInfo,
		PreAnalysis: preResult,
	}
}

func (h *SweepHandler) updateTask(task *sweepTask, status string, progress int) {
	h.mu.Lock()
	task.Status = status
	task.Progress = progress
	task.UpdatedAt = time.Now()
	h.mu.Unlock()
}

func (h *SweepHandler) updateTaskError(task *sweepTask, errMsg string) {
	h.mu.Lock()
	task.Status = "failed"
	task.Error = errMsg
	task.UpdatedAt = time.Now()
	h.mu.Unlock()
}
