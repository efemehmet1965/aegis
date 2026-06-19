package utils

import (
	"math"
	"net"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// Suspicious TLDs frequently used in phishing and scam campaigns.
var suspiciousTLDs = map[string]bool{
	"tk": true, "ml": true, "ga": true, "cf": true, "gq": true, // Freenom (free)
	"xyz": true, "top": true, "work": true, "date": true,
	"loan": true, "win": true, "download": true, "racing": true,
	"accountant": true, "bid": true, "trade": true, "webcam": true,
	"party": true, "review": true, "science": true, "stream": true,
}

// Newly-registered / disposable TLDs commonly seen in phishing.
var newlyRegisteredTLDs = map[string]bool{
	"cfd": true, "sbs": true, "click": true, "link": true,
	"cyou": true, "bond": true, "lol": true, "mom": true,
	"live": true, "rest": true, "hair": true, "makeup": true,
	"quest": true, "skin": true, "monster": true, "xyz": true,
	"pw": true, "cc": true, "su": true, "cn": true,
	"tk": true, "ml": true, "ga": true, "cf": true, "gq": true,
}

var ipPattern = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)

// NormalizeURL cleans and normalizes a URL: adds scheme if missing,
// lowercases the host, and lowercases the scheme.
func NormalizeURL(rawURL string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)

	lower := strings.ToLower(rawURL)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		rawURL = "https://" + rawURL
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	parsed.Host = strings.ToLower(parsed.Host)
	parsed.Scheme = strings.ToLower(parsed.Scheme)

	return parsed.String(), nil
}

// ExtractDomain returns the hostname portion of a URL, lowercased.
func ExtractDomain(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}

// ExtractTLD returns the top-level domain with a leading dot (e.g., ".com").
func ExtractTLD(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return ""
	}
	return "." + parts[len(parts)-1]
}

// IsSuspiciousTLD checks whether the domain uses a TLD known to be
// associated with phishing or scam activity.
func IsSuspiciousTLD(domain string) bool {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}
	tld := strings.ToLower(parts[len(parts)-1])
	return suspiciousTLDs[tld]
}

// UsesIP checks whether the URL host is a raw IP address.
func UsesIP(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return ipPattern.MatchString(parsed.Hostname())
}

// HasAtSymbol checks for @ symbols in the URL (phishing technique to
// disguise the real destination).
func HasAtSymbol(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.Contains(parsed.String(), "@")
}

// HasDoubleSlashInPath checks for "//" within the URL path (used to
// obfuscate the actual destination).
func HasDoubleSlashInPath(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.Contains(parsed.Path, "//")
}

// URLDepth returns the number of path segments in the URL.
func URLDepth(rawURL string) int {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return 0
	}
	path := strings.Trim(parsed.Path, "/")
	if path == "" {
		return 0
	}
	return len(strings.Split(path, "/"))
}

// QueryParamCount returns the number of query parameters in the URL.
func QueryParamCount(rawURL string) int {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return 0
	}
	return len(parsed.Query())
}

// IsHTTPS checks whether the URL uses the HTTPS scheme.
func IsHTTPS(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return parsed.Scheme == "https"
}

// ResolveHost performs a DNS lookup for the given domain.
func ResolveHost(domain string) ([]string, error) {
	ips, err := net.LookupHost(domain)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

// SamePrimaryDomain checks whether two domains share the same primary
// domain. Example: "login.paypal.com" and "paypal.com" returns true.
func SamePrimaryDomain(d1, d2 string) bool {
	parts1 := strings.Split(d1, ".")
	parts2 := strings.Split(d2, ".")

	if len(parts1) < 2 || len(parts2) < 2 {
		return d1 == d2
	}

	n1 := len(parts1)
	n2 := len(parts2)

	tail1 := strings.Join(parts1[max(0, n1-2):], ".")
	tail2 := strings.Join(parts2[max(0, n2-2):], ".")

	return tail1 == tail2
}

// --- Domain Entropy & Randomness Analysis ---

// DomainEntropy computes the Shannon entropy of the domain's main part
// (TLD excluded). Higher values indicate more random / auto-generated domains.
// Normal domains typically have entropy between 2.0-3.2.
func DomainEntropy(domain string) float64 {
	mainPart := MainDomainPart(domain)
	if len(mainPart) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, c := range mainPart {
		freq[c]++
	}

	var entropy float64
	length := float64(len(mainPart))
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// ConsonantVowelRatio returns the consonant-to-vowel ratio in the domain.
// Normal domains typically have a ratio of 1.0-2.5.
// Random domains often exceed 3.5 or fall below 0.3.
func ConsonantVowelRatio(domain string) float64 {
	mainPart := MainDomainPart(domain)
	vowels := 0
	consonants := 0

	for _, c := range strings.ToLower(mainPart) {
		if c >= 'a' && c <= 'z' {
			switch c {
			case 'a', 'e', 'i', 'o', 'u':
				vowels++
			default:
				consonants++
			}
		}
	}

	if vowels == 0 {
		return float64(consonants)
	}
	return float64(consonants) / float64(vowels)
}

// DigitRatio returns the proportion of numeric characters in the domain.
// Ratios above 0.30 are considered suspicious.
func DigitRatio(domain string) float64 {
	mainPart := MainDomainPart(domain)
	if len(mainPart) == 0 {
		return 0
	}

	digits := 0
	for _, c := range mainPart {
		if c >= '0' && c <= '9' {
			digits++
		}
	}
	return float64(digits) / float64(len(mainPart))
}

// HasRepeatedChars detects character repetition patterns (3+ consecutive
// identical characters) in the domain, which is common in auto-generated names.
func HasRepeatedChars(domain string) bool {
	mainPart := MainDomainPart(domain)
	if len(mainPart) < 8 {
		return false
	}

	count := 1
	prev := rune(0)
	for _, c := range mainPart {
		if c == prev {
			count++
			if count >= 3 {
				return true
			}
		} else {
			count = 1
		}
		prev = c
	}
	return false
}

// HasRandomPattern uses a composite score (entropy, CV ratio, digit ratio,
// repeated chars, length) to determine if a domain appears auto-generated.
func HasRandomPattern(domain string) bool {
	mainPart := MainDomainPart(domain)
	if len(mainPart) < 8 {
		return false
	}

	entropy := DomainEntropy(domain)
	cvRatio := ConsonantVowelRatio(domain)
	digitRatio := DigitRatio(domain)
	repeated := HasRepeatedChars(domain)

	score := 0
	if entropy > 3.5 {
		score += 2
	}
	if cvRatio > 3.5 || cvRatio < 0.3 {
		score += 2
	}
	if digitRatio > 0.3 {
		score += 1
	}
	if repeated {
		score += 2
	}
	if len(mainPart) > 20 {
		score += 1
	}

	return score >= 3
}

// DomainSuspicionScore computes a 0-100 suspicion score based entirely on
// domain structure. Useful when page content is unavailable.
func DomainSuspicionScore(domain string) int {
	mainPart := MainDomainPart(domain)
	score := 0

	if len(mainPart) > 25 {
		score += 20
	} else if len(mainPart) > 18 {
		score += 10
	}

	entropy := DomainEntropy(domain)
	if entropy > 3.8 {
		score += 25
	} else if entropy > 3.5 {
		score += 15
	} else if entropy > 3.2 {
		score += 5
	}

	cv := ConsonantVowelRatio(domain)
	if cv > 5.0 || cv < 0.2 {
		score += 20
	} else if cv > 3.5 || cv < 0.3 {
		score += 10
	}

	dr := DigitRatio(domain)
	if dr > 0.5 {
		score += 20
	} else if dr > 0.3 {
		score += 10
	}

	if HasRepeatedChars(domain) {
		score += 15
	}

	if IsSuspiciousTLD(domain) {
		score += 15
	}

	if score > 100 {
		score = 100
	}
	return score
}

// HeuristicIndicators returns a list of suspicious indicators detected
// from domain structure alone. Used for URL-only analysis when the page
// is unreachable.
func HeuristicIndicators(domain string) []string {
	var indicators []string

	if HasRandomPattern(domain) {
		indicators = append(indicators, "Auto-generated domain pattern (high entropy, unusual letter distribution)")
	}

	if len(MainDomainPart(domain)) > 25 {
		indicators = append(indicators, "Excessive domain length (26+ characters)")
	}

	entropy := DomainEntropy(domain)
	if entropy > 3.5 {
		indicators = append(indicators, "High domain entropy — likely auto-generated")
	}

	cv := ConsonantVowelRatio(domain)
	if cv > 5.0 {
		indicators = append(indicators, "Abnormal consonant density — unpronounceable domain")
	}

	dr := DigitRatio(domain)
	if dr > 0.3 {
		indicators = append(indicators, "High digit ratio in domain name")
	}

	if HasRepeatedChars(domain) {
		indicators = append(indicators, "Repeated character sequences detected")
	}

	if IsSuspiciousTLD(domain) {
		indicators = append(indicators, "Suspicious TLD")
	}

	if ipPattern.MatchString(domain) {
		indicators = append(indicators, "IP address used instead of domain name")
	}

	return indicators
}

// MainDomainPart extracts the registrable part of a domain by removing
// the TLD and returning the label immediately before it.
// Example: "sub.example.com" returns "example".
func MainDomainPart(domain string) string {
	parts := strings.Split(strings.ToLower(domain), ".")
	if len(parts) < 2 {
		return domain
	}
	return parts[len(parts)-2]
}

// HasSuspiciousSubdomain checks for deep subdomain nesting, which is
// sometimes used to disguise the real domain.
func HasSuspiciousSubdomain(domain string) bool {
	parts := strings.Split(domain, ".")
	return len(parts) > 3
}

// ContainsBrandInDomain checks if a known brand name appears in the domain.
func ContainsBrandInDomain(domain string, brands []string) string {
	lower := strings.ToLower(domain)
	for _, brand := range brands {
		if strings.Contains(lower, brand) {
			return brand
		}
	}
	return ""
}

// IsNewlyRegisteredTLD checks if the TLD is among those commonly used
// for short-lived phishing domains.
func IsNewlyRegisteredTLD(domain string) bool {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}
	tld := strings.ToLower(parts[len(parts)-1])
	return newlyRegisteredTLDs[tld]
}

// DomainWordCount estimates the number of "words" in the domain main part
// by counting consonant-vowel transitions and letter-digit boundaries.
func DomainWordCount(domain string) int {
	mainPart := MainDomainPart(domain)
	if len(mainPart) == 0 {
		return 0
	}

	count := 1
	inVowel := isVowel(rune(mainPart[0]))

	for i := 1; i < len(mainPart); i++ {
		c := rune(mainPart[i])
		prev := rune(mainPart[i-1])

		if unicode.IsDigit(c) != unicode.IsDigit(prev) {
			count++
			continue
		}

		if unicode.IsLetter(c) {
			v := isVowel(c)
			if v != inVowel && i > 1 {
				count++
			}
			inVowel = v
		}
	}

	return count
}

func isVowel(c rune) bool {
	c = unicode.ToLower(c)
	return c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u'
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
