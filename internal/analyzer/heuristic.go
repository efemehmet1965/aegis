package analyzer

import (
	"regexp"
	"strings"

	"aegis-phishing/internal/model"
	"aegis-phishing/pkg"
)

// Turkish phishing keywords commonly found in domain names targeting
// Turkish banking, government, and e-commerce users.
var turkishPhishingKeywords = []string{
	// Banking / Finance
	"banka", "bireysel", "basvuru", "kredi", "bakiye", "odemeleri",
	"taksit", "hesap", "sube", "musteri", "portali", "internet",
	"dijital", "onay", "guvenlik", "sifre", "giris", "yonetimi",
	"havale", "eft", "iban", "borsa", "yatirim", "forex", "fon",

	// Government / Institutional
	"toplukonut", "toki", "istanbulkart", "edevlet", "ptt", "sgk",
	"vergi", "tapu", "nufus", "belediye", "kamu", "resmi",
	"adalet", "emniyet", "pasaport", "ehliyet", "saglik", "asi",

	// Social Media / Tech
	"instagram", "facebook", "whatsapp", "telegram", "twitter",
	"destek", "yardim", "merkezi", "hizmet", "iletisim",
	"dogrulama", "kurtarma", "yenileme", "guncelleme",

	// E-commerce
	"siparis", "kargo", "iade", "indirim", "kampanya", "odul",
	"kazandiniz", "cek", "hediye", "firsat",

	// General phishing patterns
	"sorgula", "randevu", "basvur", "formu", "kayit", "giris",
	"login", "verify", "account", "security", "update", "confirm",
}

// Hard rule patterns: these domain patterns are always suspicious.
var hardSuspiciousPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(banka|bank|sube|kredi|hesap).*\.(xyz|cfd|sbs|click|top|tk|ml|ga|cf|gq|pw|cc|su)`),
	regexp.MustCompile(`(?i)(istanbul|ankara|turkiye|edevlet|ptt|sgk).*\.(xyz|cfd|sbs|click|top|tk|ml|ga)`),
	regexp.MustCompile(`(?i)(sorgula|randevu|basvuru).*\.(xyz|cfd|sbs|click|top)`),
}

// Free hosting / subdomain services commonly abused in phishing campaigns.
var freeHostingDomains = []string{
	"vercel.app", "nicepage.io", "netlify.app", "herokuapp.com",
	"000webhostapp.com", "blogspot.com", "wordpress.com",
	"wixsite.com", "weebly.com", "github.io", "pages.dev",
	"workers.dev", "r2.dev", "b-cdn.net", "glitch.me",
	"replit.app", "onrender.com",
}

// PreAnalyzer performs multi-layer heuristic scoring before AI classification.
// It provides a 0-100 suspicion score and a recommendation that can override
// the AI decision for high-confidence cases.
type PreAnalyzer struct{}

// NewPreAnalyzer creates a new heuristic pre-analyzer.
func NewPreAnalyzer() *PreAnalyzer {
	return &PreAnalyzer{}
}

// Analyze computes a suspicion score from domain structure, WHOIS data,
// SSL certificate status, and page content features.
func (a *PreAnalyzer) Analyze(domain string, features *model.PageFeatures, whois *model.WhoisInfo) *model.PreAnalysisResult {
	result := &model.PreAnalysisResult{
		MaxScore: 100,
	}

	domainLower := strings.ToLower(domain)
	mainPart := strings.ToLower(utils.MainDomainPart(domain))

	// ---- HARD RULES ----
	// These patterns are considered definitive indicators; they short-circuit
	// the scoring process and return immediately with a high-confidence verdict.

	// Rule 1: Hard suspicious domain patterns (keyword + TLD combinations)
	for _, pattern := range hardSuspiciousPatterns {
		if pattern.MatchString(domainLower) {
			result.TotalScore = 80
			result.Flags = append(result.Flags, "hard_rule_pattern_match")
			result.IsSuspicious = true
			result.Recommendation = "likely_phishing"
			return result
		}
	}

	// Rule 2: Free hosting with multiple phishing keywords
	if a.isFreeHosting(domainLower) {
		keywordCount := a.countPhishingKeywords(domainLower)
		if keywordCount >= 2 {
			result.TotalScore = 80
			result.Flags = append(result.Flags, "hard_rule_free_hosting_plus_keywords")
			result.IsSuspicious = true
			result.Recommendation = "likely_phishing"
			return result
		}
		if keywordCount >= 1 && a.containsNumber(domainLower) {
			result.TotalScore = 75
			result.Flags = append(result.Flags, "hard_rule_free_hosting_plus_keyword_plus_number")
			result.IsSuspicious = true
			result.Recommendation = "likely_phishing"
			return result
		}
		firstPart := strings.Split(domainLower, ".")[0]
		if len(firstPart) > 18 {
			result.TotalScore = 55
			result.Flags = append(result.Flags, "hard_rule_free_hosting_long_first_part")
			result.IsSuspicious = true
			result.Recommendation = "likely_phishing"
			return result
		}
	}

	// Rule 3: Excessively long domain + suspicious TLD + numeric content
	if len(mainPart) > 35 && utils.IsSuspiciousTLD(domain) && a.containsNumber(mainPart) {
		result.TotalScore = 65
		result.Flags = append(result.Flags, "hard_rule_long_domain_suspicious_tld_number")
		result.IsSuspicious = true
		result.Recommendation = "likely_phishing"
		return result
	}

	// ---- LAYERED SCORING ----
	// Falls through to weighted scoring when no hard rule fires.

	score := 0

	// Layer 1: Domain structure (max 30 points)
	entropy := utils.DomainEntropy(domain)
	if entropy > 3.8 {
		score += 15
		result.Flags = append(result.Flags, "domain_very_high_entropy")
	} else if entropy > 3.5 {
		score += 10
		result.Flags = append(result.Flags, "domain_high_entropy")
	} else if entropy > 3.2 {
		score += 5
	}

	cv := utils.ConsonantVowelRatio(domain)
	if cv > 5.0 || cv < 0.2 {
		score += 10
		result.Flags = append(result.Flags, "domain_extreme_cv_ratio")
	} else if cv > 3.5 || cv < 0.3 {
		score += 5
	}

	dr := utils.DigitRatio(domain)
	if dr > 0.5 {
		score += 10
		result.Flags = append(result.Flags, "domain_high_digit_ratio")
	} else if dr > 0.3 {
		score += 5
	}

	if utils.HasRepeatedChars(domain) {
		score += 5
		result.Flags = append(result.Flags, "domain_repeated_chars")
	}

	if len(mainPart) > 30 {
		score += 10
		result.Flags = append(result.Flags, "domain_excessive_length")
	} else if len(mainPart) > 22 {
		score += 5
	}

	if utils.HasRandomPattern(domain) {
		score += 10
		result.Flags = append(result.Flags, "domain_random_pattern")
	}

	result.TotalScore += clamp(score, 0, 30)
	score = 0

	// Layer 2: Content / keyword analysis (max 25 points)
	keywordCount := a.countPhishingKeywords(domainLower)
	if keywordCount >= 3 {
		score += 20
		result.Flags = append(result.Flags, "multiple_phishing_keywords")
	} else if keywordCount >= 2 {
		score += 15
		result.Flags = append(result.Flags, "phishing_keywords_detected")
	} else if keywordCount >= 1 {
		score += 8
		result.Flags = append(result.Flags, "phishing_keyword_detected")
	}

	if keywordCount >= 1 && a.containsNumber(mainPart) {
		score += 5
		result.Flags = append(result.Flags, "keyword_plus_numbers")
	}

	result.TotalScore += clamp(score, 0, 25)
	score = 0

	// Layer 3: TLD and domain type (max 20 points)
	if utils.IsSuspiciousTLD(domain) {
		score += 10
		result.Flags = append(result.Flags, "suspicious_tld")
	}
	if utils.IsNewlyRegisteredTLD(domain) {
		score += 5
		result.Flags = append(result.Flags, "newly_registered_tld")
	}
	if utils.HasSuspiciousSubdomain(domain) {
		score += 5
		result.Flags = append(result.Flags, "suspicious_subdomain")
	}
	if a.isFreeHosting(domainLower) {
		score += 10
		result.Flags = append(result.Flags, "free_hosting")
	}

	result.TotalScore += clamp(score, 0, 20)
	score = 0

	// Layer 4: WHOIS data (max 25 points)
	if whois != nil {
		if whois.IsVeryNew {
			score += 15
			result.Flags = append(result.Flags, "domain_very_new_30d")
		} else if whois.IsNewlyRegistered {
			score += 10
			result.Flags = append(result.Flags, "domain_new_90d")
		}
		if whois.IsFreeHosting {
			score += 10
			result.Flags = append(result.Flags, "free_hosting_whois")
		}
	}

	result.TotalScore += clamp(score, 0, 25)
	score = 0

	// Layer 5: SSL and connection (max 15 points)
	if features != nil {
		if features.SSLInfo != nil {
			if !features.SSLInfo.Valid || features.SSLInfo.IsSelfSigned {
				score += 10
				result.Flags = append(result.Flags, "ssl_invalid_or_selfsigned")
			}
			if features.SSLInfo.IsExpired {
				score += 5
				result.Flags = append(result.Flags, "ssl_expired")
			}
		}
		if features.URLUsesIP {
			score += 10
			result.Flags = append(result.Flags, "url_uses_ip")
		}
		if features.URLHasAtSymbol || features.URLHasDoubleSlash {
			score += 5
			result.Flags = append(result.Flags, "url_suspicious_chars")
		}
	}

	result.TotalScore += clamp(score, 0, 15)
	score = 0

	// Layer 6: Page content (max 10 points)
	if features != nil {
		if features.HasPasswordField && features.FormActionExternal {
			score += 10
			result.Flags = append(result.Flags, "credential_harvesting_form")
		} else if features.HasPasswordField {
			score += 5
		}
	}

	result.TotalScore += clamp(score, 0, 10)

	// Final classification
	result.IsSuspicious = result.TotalScore >= 25

	switch {
	case result.TotalScore >= 50:
		result.Recommendation = "likely_phishing"
	case result.TotalScore >= 25:
		result.Recommendation = "needs_ai"
	default:
		result.Recommendation = "likely_safe"
	}

	return result
}

func (a *PreAnalyzer) isFreeHosting(domain string) bool {
	for _, host := range freeHostingDomains {
		if strings.HasSuffix(domain, host) {
			return true
		}
	}
	return false
}

func (a *PreAnalyzer) countPhishingKeywords(domain string) int {
	count := 0
	domainLower := strings.ToLower(domain)
	for _, keyword := range turkishPhishingKeywords {
		if strings.Contains(domainLower, keyword) {
			count++
		}
	}
	return count
}

func (a *PreAnalyzer) containsNumber(s string) bool {
	for _, c := range s {
		if c >= '0' && c <= '9' {
			return true
		}
	}
	return false
}

func clamp(val, min, max int) int {
	if val < min {
		return min
	}
	if val > max {
		return max
	}
	return val
}
