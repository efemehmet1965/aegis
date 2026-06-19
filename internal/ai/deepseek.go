package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"aegis-phishing/config"
	"aegis-phishing/internal/model"
)

// deepseekProvider implements the AIProvider interface using the DeepSeek API
// (OpenAI-compatible chat completions endpoint).
type deepseekProvider struct {
	cfg        *config.Config
	httpClient *http.Client
}

// NewDeepSeek creates a new DeepSeek AI provider.
func NewDeepSeek(cfg *config.Config) AIProvider {
	return &deepseekProvider{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

func (d *deepseekProvider) Name() string {
	return "deepseek"
}

// ---- API Message Types ----

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
	MaxTokens   int           `json:"max_tokens"`
}

type chatResponse struct {
	ID      string `json:"id"`
	Choices []struct {
		Index   int         `json:"index"`
		Message chatMessage `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error,omitempty"`
}

// Analyze sends the URL and extracted features to DeepSeek for threat classification.
// Uses few-shot prompting with labeled examples of phishing and legitimate sites.
func (d *deepseekProvider) Analyze(ctx context.Context, url string, features *model.PageFeatures) (*model.AIAnalysis, error) {
	systemPrompt := d.buildSystemPrompt()
	userPrompt := d.buildUserPrompt(url, features)

	chatReq := chatRequest{
		Model: d.cfg.DeepSeekModel,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
		Temperature: 0.1, // Low temperature for consistent classification
		MaxTokens:   1024,
	}

	reqBody, err := json.Marshal(chatReq)
	if err != nil {
		return nil, fmt.Errorf("request marshal failed: %w", err)
	}

	apiURL := d.cfg.DeepSeekBaseURL + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("API request creation failed: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+d.cfg.DeepSeekAPIKey)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API call failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("response read failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error: HTTP %d - %s", resp.StatusCode, string(body))
	}

	var chatResp chatResponse
	if err := json.Unmarshal(body, &chatResp); err != nil {
		return nil, fmt.Errorf("response parse failed: %w", err)
	}

	if chatResp.Error != nil {
		return nil, fmt.Errorf("API error: %s", chatResp.Error.Message)
	}

	if len(chatResp.Choices) == 0 {
		return nil, fmt.Errorf("API returned empty response")
	}

	content := chatResp.Choices[0].Message.Content
	analysis, err := d.parseAnalysis(content)
	if err != nil {
		return nil, fmt.Errorf("AI response parse failed: %w\nResponse: %s", err, content)
	}

	return analysis, nil
}

// buildSystemPrompt constructs the system prompt with threat indicators,
// classification taxonomy, and few-shot examples for accurate labeling.
func (d *deepseekProvider) buildSystemPrompt() string {
	return `You are a senior cyber threat intelligence analyst with 10+ years of experience detecting phishing campaigns, financial fraud, and malicious infrastructure.

Your task is to classify URLs based on extracted forensic features and provide structured threat labels.

## THREAT INDICATORS (ordered by severity):

### CRITICAL (individually sufficient):
1. Random/auto-generated domain (entropy >3.5, unpronounceable, meaningless character sequence)
2. Brand impersonation + suspicious TLD
3. Domain age <30 days + suspicious TLD or self-signed SSL
4. Completely invalid/self-signed SSL + password form
5. Domain suspicion score >60/100

### HIGH:
6. Suspicious TLD (.xyz, .cfd, .sbs, .click, .tk, .ml, .ga, .top, .work, .online, .site)
7. Recently registered domain (<90 days)
8. Free hosting service (vercel.app, nicepage.io, netlify.app, github.io, b-cdn.net, etc.)
9. Raw IP address used instead of domain name
10. Password field + form action pointing to external domain

### MEDIUM:
11. High external link ratio (>50%)
12. @ symbol in URL or double-slash in path
13. Hidden form inputs (redirect parameters)
14. Excessively long or complex URL structure

## FEW-SHOT EXAMPLES:

### Example 1 — PHISHING (random domain):
URL: frsttlrrrkmpnyaabsvrrrrsonnnn.xyz
Domain: entropy=3.9, cv_ratio=4.5, length=30, suspicious_tld=true, suspicion_score=75
SSL: self-signed, Let's Encrypt
Page: unreachable
RESULT: {"is_threat": true, "label": "generic_phishing", "category": "phishing", "confidence": 0.98, "risk_level": "critical", "reasons": ["Auto-generated domain (entropy 3.9, 30-char meaningless string)", "Suspicious TLD .xyz", "Self-signed SSL", "Domain is unpronounceable — not human-created"], "indicators": ["random_domain", "suspicious_tld", "self_signed_ssl", "excessive_length"]}

### Example 2 — GOVERNMENT PHISHING:
URL: istanbulkartrandevuu.xyz
Domain: entropy=2.8, cv_ratio=2.1, suspicious_tld=true, suspicion_score=40
SSL: valid, Let's Encrypt
Page: Uses Istanbulkart branding, has application form
RESULT: {"is_threat": true, "label": "government_phishing", "category": "phishing", "confidence": 0.92, "risk_level": "high", "reasons": ["Impersonating Istanbulkart (municipal government entity)", "Suspicious TLD .xyz instead of .bel.tr or .com.tr", "Uses free Let's Encrypt SSL"], "indicators": ["brand_impersonation", "typosquatting", "suspicious_tld", "government_entity"]}

### Example 3 — SAFE:
URL: sellnightcare.com
Domain: entropy=2.9, cv_ratio=1.8, length=14, suspicious_tld=false, suspicion_score=5, age=163 days
SSL: valid, standard issuer
Page: Skincare e-commerce site
RESULT: {"is_threat": false, "label": "safe", "category": "safe", "confidence": 0.95, "risk_level": "safe", "reasons": ["Normal domain structure", "Valid SSL from standard CA", "Legitimate e-commerce content"], "indicators": []}

### Example 4 — BANKING PHISHING (new domain):
URL: dijital-bireyselbasvurulariniz.sbs
Domain: entropy=3.1, cv_ratio=1.9, length=31, suspicious_tld=true (.sbs), age=2 days
SSL: self-signed
Page: Banking application form imitation
RESULT: {"is_threat": true, "label": "banking_phishing", "category": "phishing", "confidence": 0.92, "risk_level": "high", "reasons": ["Domain registered only 2 days ago", "Phishing-associated TLD .sbs", "Self-signed SSL certificate", "Contains banking terms but is not an official bank domain"], "indicators": ["brand_new_domain", "suspicious_tld", "self_signed_ssl", "financial_terms"]}

### Example 5 — PHISHING (page down, domain analysis only):
URL: t74909303.click
Domain: entropy=2.5, digit_ratio=89%, suspicious_tld=true (.click)
SSL: invalid
Page: 403 error
RESULT: {"is_threat": true, "label": "generic_phishing", "category": "phishing", "confidence": 0.85, "risk_level": "high", "reasons": ["Domain is 89% digits — auto-generated pattern", "Suspicious TLD .click", "Invalid SSL certificate"], "indicators": ["random_domain", "high_digit_ratio", "suspicious_tld"]}

## RULES:
1. If domain_suspicion_score >50, classify as threat regardless of page content
2. If domain entropy >3.5 AND suspicious TLD, classify as threat
3. If domain age <30 days AND (suspicious TLD OR invalid SSL), classify as threat
4. Classify based on domain analysis even when page is unreachable
5. Assign realistic confidence values: 0.98 (definitive), 0.85-0.92 (strong), 0.70-0.80 (moderate), 0.50-0.65 (weak)
6. For free hosting subdomains (vercel.app, nicepage.io, etc.), the WHOIS age belongs to the base domain and is misleading — ignore it and focus on the subdomain structure

## CLASSIFICATION TAXONOMY:
Categories and their labels:
- phishing: banking_phishing, social_media_phishing, government_phishing, ecommerce_scam, investment_scam, credential_harvesting, generic_phishing
- malware: malware, cryptominer
- harmful_content: gambling, adult_content, fake_news, spam
- parked: parked_domain, defaced
- safe: safe

Return ONLY valid JSON, no other text:
{
  "is_threat": true/false,
  "label": "one of the labels above",
  "category": "one of the categories above",
  "confidence": 0.0-1.0,
  "risk_level": "critical|high|medium|low|safe",
  "reasons": ["reason 1", "reason 2", ...],
  "indicators": ["indicator_1", "indicator_2", ...],
  "domain_flags": {
    "suspicious_tld": true/false,
    "typosquatting": true/false,
    "recently_registered": true/false/null,
    "imitates_brand": "brand name or empty string",
    "uses_free_hosting": true/false,
    "url_length_excessive": true/false
  }
}`
}

// buildUserPrompt assembles the feature report for the AI to analyze.
func (d *deepseekProvider) buildUserPrompt(url string, f *model.PageFeatures) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Analyze the following URL for threats:\n\n"))
	sb.WriteString(fmt.Sprintf("URL: %s\n\n", url))
	sb.WriteString("=== EXTRACTED FEATURES ===\n\n")

	sb.WriteString("-- URL Analysis --\n")
	sb.WriteString(fmt.Sprintf("- HTTPS: %v\n", f.URLIsHTTPS))
	sb.WriteString(fmt.Sprintf("- Uses IP address: %v\n", f.URLUsesIP))
	sb.WriteString(fmt.Sprintf("- Suspicious TLD: %v\n", f.URLHasSuspiciousTLD))
	sb.WriteString(fmt.Sprintf("- URL depth: %d\n", f.URLDepth))
	sb.WriteString(fmt.Sprintf("- Query parameters: %d\n", f.URLQueryParams))
	sb.WriteString(fmt.Sprintf("- Uses @ symbol: %v\n", f.URLHasAtSymbol))
	sb.WriteString(fmt.Sprintf("- Mid-URL double-slash: %v\n", f.URLHasDoubleSlash))

	sb.WriteString("\n-- Domain Randomness Analysis --\n")
	sb.WriteString(fmt.Sprintf("- Entropy: %.2f (>3.5 = random)\n", f.DomainEntropy))
	sb.WriteString(fmt.Sprintf("- Consonant/Vowel ratio: %.2f (normal: 1.0-2.5)\n", f.DomainCVRatio))
	sb.WriteString(fmt.Sprintf("- Digit ratio: %.2f\n", f.DomainDigitRatio))
	sb.WriteString(fmt.Sprintf("- Length: %d characters\n", f.DomainLength))
	sb.WriteString(fmt.Sprintf("- Estimated word count: %d\n", f.DomainWordCount))
	sb.WriteString(fmt.Sprintf("- Repeated characters: %v\n", f.DomainHasRepeatedChars))
	sb.WriteString(fmt.Sprintf("- Random pattern detected: %v\n", f.DomainHasRandomPattern))
	sb.WriteString(fmt.Sprintf("- Domain suspicion score: %d/100\n", f.DomainSuspicionScore))
	if len(f.HeuristicFlags) > 0 {
		sb.WriteString(fmt.Sprintf("- Heuristic flags: %v\n", f.HeuristicFlags))
	}

	// WHOIS data
	if f.WhoisInfo != nil {
		sb.WriteString("\n-- WHOIS / Domain Registration --\n")
		if f.WhoisInfo.Error != "" {
			sb.WriteString(fmt.Sprintf("- WHOIS error: %s\n", f.WhoisInfo.Error))
		} else {
			sb.WriteString(fmt.Sprintf("- Domain age: %d days\n", f.WhoisInfo.DomainAgeDays))
			sb.WriteString(fmt.Sprintf("- Very new (<30 days): %v\n", f.WhoisInfo.IsVeryNew))
			sb.WriteString(fmt.Sprintf("- Newly registered (<90 days): %v\n", f.WhoisInfo.IsNewlyRegistered))
			if f.WhoisInfo.CreationDate != nil {
				sb.WriteString(fmt.Sprintf("- Creation date: %s\n", f.WhoisInfo.CreationDate.Format("2006-01-02")))
			}
			sb.WriteString(fmt.Sprintf("- Registrar: %s\n", f.WhoisInfo.Registrar))
			sb.WriteString(fmt.Sprintf("- Free hosting: %v\n", f.WhoisInfo.IsFreeHosting))
		}
	}

	sb.WriteString("\n-- Page Metadata --\n")
	sb.WriteString(fmt.Sprintf("- Title: %s\n", truncate(f.Title, 200)))
	sb.WriteString(fmt.Sprintf("- Meta Description: %s\n", truncate(f.MetaDescription, 200)))

	sb.WriteString("\n-- Form Analysis --\n")
	sb.WriteString(fmt.Sprintf("- Has form: %v\n", f.HasForm))
	sb.WriteString(fmt.Sprintf("- Has password field: %v\n", f.HasPasswordField))
	sb.WriteString(fmt.Sprintf("- Form action to external domain: %v\n", f.FormActionExternal))
	sb.WriteString(fmt.Sprintf("- Form actions: %v\n", f.FormActions))
	sb.WriteString(fmt.Sprintf("- Form methods: %v\n", f.FormMethods))
	sb.WriteString(fmt.Sprintf("- Input names: %v\n", f.InputNames))
	if len(f.HiddenInputNames) > 0 {
		sb.WriteString(fmt.Sprintf("- Hidden inputs: %v\n", f.HiddenInputNames))
	}

	sb.WriteString("\n-- Link Analysis --\n")
	sb.WriteString(fmt.Sprintf("- Total links: %d\n", f.TotalLinks))
	sb.WriteString(fmt.Sprintf("- Internal links: %d\n", f.InternalLinks))
	sb.WriteString(fmt.Sprintf("- External links: %d\n", f.ExternalLinks))
	sb.WriteString(fmt.Sprintf("- External link ratio: %.2f\n", f.ExternalLinkRatio))
	if len(f.ExternalDomains) > 0 && len(f.ExternalDomains) <= 20 {
		sb.WriteString(fmt.Sprintf("- External domains: %v\n", f.ExternalDomains))
	} else if len(f.ExternalDomains) > 20 {
		sb.WriteString(fmt.Sprintf("- External domains: %v... (%d total)\n",
			f.ExternalDomains[:20], len(f.ExternalDomains)))
	}

	sb.WriteString("\n-- Page Content --\n")
	sb.WriteString(fmt.Sprintf("- Visible text length: %d characters\n", f.TextLength))
	sb.WriteString(fmt.Sprintf("- Visible text (first 1000 chars):\n  %s\n", truncate(f.VisibleText, 1000)))

	sb.WriteString(fmt.Sprintf("\n-- Script/iframe Counts --\n"))
	sb.WriteString(fmt.Sprintf("- Scripts: %d (external: %d)\n", f.ScriptCount, f.ExternalScripts))
	sb.WriteString(fmt.Sprintf("- Iframes: %d\n", f.IframeCount))

	if f.SSLInfo != nil {
		sb.WriteString("\n-- SSL Certificate --\n")
		sb.WriteString(fmt.Sprintf("- Valid: %v\n", f.SSLInfo.Valid))
		sb.WriteString(fmt.Sprintf("- Issuer: %s\n", f.SSLInfo.Issuer))
		sb.WriteString(fmt.Sprintf("- Self-signed: %v\n", f.SSLInfo.IsSelfSigned))
		sb.WriteString(fmt.Sprintf("- Expired: %v\n", f.SSLInfo.IsExpired))
		sb.WriteString(fmt.Sprintf("- Days remaining: %d\n", f.SSLInfo.DaysRemaining))
	}

	sb.WriteString("\n=== PROVIDE YOUR ANALYSIS (JSON only) ===")

	return sb.String()
}

// parseAnalysis extracts the structured AIAnalysis from the LLM response.
// Handles markdown code blocks around the JSON and validates labels.
func (d *deepseekProvider) parseAnalysis(content string) (*model.AIAnalysis, error) {
	content = strings.TrimSpace(content)

	// Handle markdown code fences: ```json ... ```
	if strings.HasPrefix(content, "```") {
		end := strings.LastIndex(content, "```")
		start := strings.Index(content, "\n")
		if start != -1 && end > start {
			content = content[start:end]
		}
		content = strings.Trim(content, "`")
	}

	analysis := &model.AIAnalysis{}
	if err := json.Unmarshal([]byte(content), analysis); err != nil {
		return nil, fmt.Errorf("JSON parse error: %w", err)
	}

	// Validate and normalize the label
	if _, ok := model.ValidLabels[analysis.Label]; !ok {
		if analysis.IsThreat {
			analysis.Label = "generic_phishing"
			analysis.Category = "phishing"
		} else {
			analysis.Label = "safe"
			analysis.Category = "safe"
		}
	}

	// Ensure category matches the label (correct AI mistakes)
	if expectedCat, ok := model.ValidLabels[analysis.Label]; ok {
		analysis.Category = expectedCat
	}

	return analysis, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
