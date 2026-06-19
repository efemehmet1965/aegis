package fetcher

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"aegis-phishing/config"
	"aegis-phishing/internal/model"
)

var (
	creationDatePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)Creation Date:\s*(.+)`),
		regexp.MustCompile(`(?i)Created:\s*(.+)`),
		regexp.MustCompile(`(?i)created:\s*(.+)`),
		regexp.MustCompile(`(?i)Registered on:\s*(.+)`),
		regexp.MustCompile(`(?i)Registration Date:\s*(.+)`),
		regexp.MustCompile(`(?i)Domain Registration Date:\s*(.+)`),
		regexp.MustCompile(`(?i)Creation Date \(dd/mm/yyyy\):\s*(.+)`),
		regexp.MustCompile(`(?i)created-date:\s*(.+)`),
	}

	trCreationPattern = regexp.MustCompile(`(?i)Created on\.+:\s*(\d{4}-\w{3}-\d{2})`)

	registrarPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)Registrar:\s*(.+)`),
		regexp.MustCompile(`(?i)Registrar Name:\s*(.+)`),
		regexp.MustCompile(`(?i)Sponsoring Registrar:\s*(.+)`),
	}

	whoisServers = map[string]string{
		"com":    "whois.verisign-grs.com",
		"net":    "whois.verisign-grs.com",
		"org":    "whois.pir.org",
		"io":     "whois.nic.io",
		"xyz":    "whois.nic.xyz",
		"tk":     "whois.nic.tk",
		"ml":     "whois.nic.ml",
		"cf":     "whois.nic.cf",
		"ga":     "whois.nic.ga",
		"click":  "whois.nic.click",
		"cfd":    "whois.nic.cfd",
		"sbs":    "whois.nic.sbs",
		"top":    "whois.nic.top",
		"work":   "whois.nic.work",
		"online": "whois.nic.online",
		"site":   "whois.nic.site",
		"app":    "whois.nic.app",
	}
)

// WhoisFetcher queries WHOIS servers for domain registration information.
type WhoisFetcher struct {
	cfg *config.Config
}

// NewWhoisFetcher creates a new WHOIS lookup service.
func NewWhoisFetcher(cfg *config.Config) *WhoisFetcher {
	return &WhoisFetcher{cfg: cfg}
}

// Lookup queries WHOIS for the given domain and extracts creation date,
// registrar, and domain age metrics.
func (w *WhoisFetcher) Lookup(ctx context.Context, domain string) *model.WhoisInfo {
	info := &model.WhoisInfo{
		Domain: domain,
	}

	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		info.Error = "invalid domain format"
		return info
	}
	tld := strings.ToLower(parts[len(parts)-1])

	server, ok := whoisServers[tld]
	if !ok {
		server = "whois.iana.org"
	}

	raw, err := w.queryWhois(ctx, domain, server)
	if err != nil {
		if server != "whois.iana.org" {
			raw, err = w.queryWhois(ctx, domain, "whois.iana.org")
		}
		if err != nil {
			info.Error = err.Error()
			return info
		}
	}

	info.RawResponse = truncateStr(raw, 500)
	info.CreationDate = extractCreationDate(raw, tld)
	info.Registrar = extractRegistrar(raw)

	if info.CreationDate != nil {
		info.DomainAgeDays = int(time.Since(*info.CreationDate).Hours() / 24)
		info.IsNewlyRegistered = info.DomainAgeDays < 90
		info.IsVeryNew = info.DomainAgeDays < 30
	}

	info.IsFreeHosting = isFreeHosting(domain)

	return info
}

func (w *WhoisFetcher) queryWhois(ctx context.Context, domain, server string) (string, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}

	conn, err := dialer.DialContext(ctx, "tcp", server+":43")
	if err != nil {
		return "", fmt.Errorf("whois connection failed: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	query := domain + "\r\n"
	if _, err := conn.Write([]byte(query)); err != nil {
		return "", fmt.Errorf("whois query failed: %w", err)
	}

	var response strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			response.Write(buf[:n])
		}
		if err != nil {
			break
		}
		if response.Len() > 65536 {
			break
		}
	}

	return response.String(), nil
}

func extractCreationDate(raw, tld string) *time.Time {
	if tld == "tr" {
		if match := trCreationPattern.FindStringSubmatch(raw); len(match) > 1 {
			if t, err := time.Parse("2006-Jan-02", strings.TrimSpace(match[1])); err == nil {
				return &t
			}
		}
	}

	for _, pattern := range creationDatePatterns {
		if match := pattern.FindStringSubmatch(raw); len(match) > 1 {
			dateStr := strings.TrimSpace(match[1])
			for _, layout := range []string{
				"2006-01-02T15:04:05Z",
				"2006-01-02T15:04:05-07:00",
				"2006-01-02 15:04:05",
				"2006-01-02",
				"02-Jan-2006",
				"January 02 2006",
				"2006/01/02",
				"02.01.2006",
				"2006.01.02",
				time.RFC3339,
				time.RFC1123,
			} {
				if t, err := time.Parse(layout, dateStr); err == nil {
					return &t
				}
			}
		}
	}
	return nil
}

func extractRegistrar(raw string) string {
	for _, pattern := range registrarPatterns {
		if match := pattern.FindStringSubmatch(raw); len(match) > 1 {
			return strings.TrimSpace(match[1])
		}
	}
	return ""
}

func isFreeHosting(domain string) bool {
	hosts := []string{
		"nicepage.io", "vercel.app", "netlify.app", "herokuapp.com",
		"000webhostapp.com", "blogspot.com", "wordpress.com",
		"wixsite.com", "weebly.com", "github.io", "pages.dev",
		"workers.dev", "r2.dev", "b-cdn.net", "glitch.me",
		"replit.app", "onrender.com",
	}

	domainLower := strings.ToLower(domain)
	for _, host := range hosts {
		if strings.HasSuffix(domainLower, host) {
			return true
		}
	}
	return false
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
