package model

import "time"

// --- Request Types ---

// CheckRequest is the request payload for single-URL analysis.
type CheckRequest struct {
	URL string `json:"url"`
}

// SweepRequest is the request payload for reverse IP + bulk scanning.
type SweepRequest struct {
	URL          string `json:"url"`
	ScanSiblings bool   `json:"scan_siblings"`
}

// --- Response Types ---

// CheckResponse is the result of a single-URL threat analysis.
type CheckResponse struct {
	URL          string              `json:"url"`
	IsThreat     bool                `json:"is_threat"`
	Label        string              `json:"label"`
	Category     string              `json:"category"`
	Confidence   float64             `json:"confidence"`
	Analysis     *AIAnalysis         `json:"analysis"`
	Features     *PageFeatures       `json:"features"`
	SSLInfo      *SSLInfo            `json:"ssl_info,omitempty"`
	FetchError   string              `json:"fetch_error,omitempty"`
	PreAnalysis  *PreAnalysisResult  `json:"pre_analysis,omitempty"`
	SiblingSites []SiblingInfo       `json:"sibling_sites,omitempty"`
}

// SweepResponse is the result of a sweep operation (original + sibling scans).
type SweepResponse struct {
	Original       CheckResponse    `json:"original"`
	IP             string           `json:"ip"`
	ReverseIP      *ReverseIPResult `json:"reverse_ip_lookup"`
	SiblingResults []CheckResponse  `json:"sibling_results"`
	Summary        *SweepSummary    `json:"summary"`
}

// ErrorResponse is returned on error conditions.
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    int    `json:"code"`
	Details string `json:"details,omitempty"`
}

// HealthResponse is returned by the health check endpoint.
type HealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
	Uptime  string `json:"uptime"`
}

// --- Page Features ---

// PageFeatures holds forensic features extracted from a URL and its HTML content.
type PageFeatures struct {
	// Page metadata
	Title           string `json:"title"`
	MetaDescription string `json:"meta_description"`
	FaviconURL      string `json:"favicon_url,omitempty"`

	// Form analysis
	HasForm            bool     `json:"has_form"`
	HasPasswordField   bool     `json:"has_password_field"`
	FormActions        []string `json:"form_actions"`
	FormActionExternal bool     `json:"form_action_external"`
	FormMethods        []string `json:"form_methods"`
	HiddenInputNames   []string `json:"hidden_input_names,omitempty"`
	InputNames         []string `json:"input_names,omitempty"`

	// Link analysis
	TotalLinks        int      `json:"total_links"`
	ExternalLinks     int      `json:"external_links"`
	InternalLinks     int      `json:"internal_links"`
	ExternalLinkRatio float64  `json:"external_link_ratio"`
	UniqueDomains     []string `json:"unique_domains"`
	ExternalDomains   []string `json:"external_domains"`
	BrokenLinks       int      `json:"broken_links,omitempty"`

	// Visible content
	VisibleText string `json:"visible_text"`
	TextLength  int    `json:"text_length"`

	// Script analysis
	ScriptCount     int `json:"script_count"`
	ExternalScripts int `json:"external_scripts"`
	IframeCount     int `json:"iframe_count"`

	// URL structure analysis
	URLUsesIP           bool `json:"url_uses_ip"`
	URLHasSuspiciousTLD bool `json:"url_has_suspicious_tld"`
	URLDepth            int  `json:"url_depth"`
	URLQueryParams      int  `json:"url_query_params"`
	URLIsHTTPS          bool `json:"url_is_https"`
	URLHasAtSymbol      bool `json:"url_has_at_symbol"`
	URLHasDoubleSlash   bool `json:"url_has_double_slash_mid"`

	// Domain randomness analysis
	DomainEntropy         float64  `json:"domain_entropy"`
	DomainCVRatio         float64  `json:"domain_cv_ratio"`
	DomainDigitRatio      float64  `json:"domain_digit_ratio"`
	DomainSuspicionScore  int      `json:"domain_suspicion_score"`
	DomainHasRandomPattern bool    `json:"domain_has_random_pattern"`
	DomainHasRepeatedChars bool    `json:"domain_has_repeated_chars"`
	DomainLength          int      `json:"domain_length"`
	DomainWordCount       int      `json:"domain_word_count"`
	HeuristicFlags        []string `json:"heuristic_flags,omitempty"`

	// External data (attached after parsing)
	WhoisInfo *WhoisInfo `json:"whois_info,omitempty"`
	SSLInfo   *SSLInfo   `json:"ssl_info,omitempty"`
}

// PreAnalysisResult is the output of the multi-layer heuristic pre-scoring phase.
type PreAnalysisResult struct {
	TotalScore     int      `json:"total_score"`
	MaxScore       int      `json:"max_score"`
	Flags          []string `json:"flags"`
	IsSuspicious   bool     `json:"is_suspicious"`
	Recommendation string   `json:"recommendation"` // likely_phishing, needs_ai, likely_safe
}

// --- WHOIS ---

// WhoisInfo holds domain registration data retrieved from WHOIS lookup.
type WhoisInfo struct {
	Domain            string     `json:"domain"`
	CreationDate      *time.Time `json:"creation_date,omitempty"`
	DomainAgeDays     int        `json:"domain_age_days"`
	IsNewlyRegistered bool       `json:"is_newly_registered"`
	IsVeryNew         bool       `json:"is_very_new"`
	Registrar         string     `json:"registrar,omitempty"`
	IsFreeHosting     bool       `json:"is_free_hosting"`
	RawResponse       string     `json:"raw_response,omitempty"`
	Error             string     `json:"error,omitempty"`
}

// --- SSL / TLS ---

// SSLInfo holds TLS certificate information extracted during the HTTP connection.
type SSLInfo struct {
	Valid         bool      `json:"valid"`
	Issuer        string    `json:"issuer"`
	Subject       string    `json:"subject"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	DaysRemaining int       `json:"days_remaining"`
	IsExpired     bool      `json:"is_expired"`
	IsSelfSigned  bool      `json:"is_self_signed"`
	DNSNames      []string  `json:"dns_names,omitempty"`
	Version       int       `json:"version"`
}

// --- AI Analysis Result ---

// AIAnalysis is the structured threat classification returned by the LLM.
type AIAnalysis struct {
	IsThreat    bool        `json:"is_threat"`
	Label       string      `json:"label"`
	Category    string      `json:"category"`
	Confidence  float64     `json:"confidence"`
	RiskLevel   string      `json:"risk_level"` // critical, high, medium, low, safe
	Reasons     []string    `json:"reasons"`
	Indicators  []string    `json:"indicators,omitempty"`
	DomainFlags DomainFlags `json:"domain_flags"`
}

// DomainFlags holds domain-level suspicion indicators.
type DomainFlags struct {
	SuspiciousTLD      bool   `json:"suspicious_tld"`
	Typosquatting      bool   `json:"typosquatting"`
	RecentlyRegistered *bool  `json:"recently_registered"` // nil = unknown
	ImitatesBrand      string `json:"imitates_brand,omitempty"`
	UsesFreeHosting    bool   `json:"uses_free_hosting"`
	URLLengthExcessive bool   `json:"url_length_excessive"`
}

// ValidLabels maps each supported threat label to its parent category.
var ValidLabels = map[string]string{
	// Phishing subtypes
	"banking_phishing":      "phishing",
	"social_media_phishing": "phishing",
	"government_phishing":   "phishing",
	"ecommerce_scam":        "phishing",
	"investment_scam":       "phishing",
	"credential_harvesting": "phishing",
	"generic_phishing":      "phishing",

	// Malware
	"malware":     "malware",
	"cryptominer": "malware",

	// Harmful content
	"gambling":      "harmful_content",
	"adult_content": "harmful_content",
	"fake_news":     "harmful_content",
	"spam":          "harmful_content",

	// Parked / inactive
	"parked_domain": "parked",
	"defaced":       "parked",

	// Benign
	"safe": "safe",
}

// ValidCategories is the set of recognized threat categories.
var ValidCategories = map[string]bool{
	"phishing": true, "malware": true, "harmful_content": true,
	"parked": true, "safe": true,
}

// --- Reverse IP Lookup ---

// ReverseIPResult holds the domains discovered on the same IP address.
type ReverseIPResult struct {
	IP           string   `json:"ip"`
	TotalDomains int      `json:"total_domains"`
	DomainsFound []string `json:"domains_found"`
	Source       string   `json:"source"` // hackertarget, viewdns, dns_ptr
}

// SiblingInfo is a lightweight reference to a co-hosted domain.
type SiblingInfo struct {
	Domain     string `json:"domain"`
	URL        string `json:"url"`
	IsThreat   *bool  `json:"is_threat,omitempty"` // nil = not yet scanned
}

// SweepSummary holds aggregate statistics from a sweep operation.
type SweepSummary struct {
	TotalScanned             int     `json:"total_scanned"`
	PhishingDetected         int     `json:"phishing_detected"`
	PhishingRatio            float64 `json:"phishing_ratio"`
	LikelyBulletproofHosting bool    `json:"likely_bulletproof_hosting"`
	SkippedCount             int     `json:"skipped_count"`
	ErrorCount               int     `json:"error_count"`
}
