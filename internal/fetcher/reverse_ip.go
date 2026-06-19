package fetcher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"aegis-phishing/config"
	"aegis-phishing/internal/model"
)

// ReverseIPFetcher discovers domains hosted on the same IP address.
type ReverseIPFetcher struct {
	cfg        *config.Config
	httpClient *http.Client
}

// NewReverseIPFetcher creates a new reverse IP lookup service.
func NewReverseIPFetcher(cfg *config.Config) *ReverseIPFetcher {
	return &ReverseIPFetcher{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// Lookup resolves the domain to an IP address, then queries reverse IP
// services to find other domains on the same IP. Tries methods in order:
// HackerTarget (free, rate-limited), ViewDNS (requires API key), DNS PTR records.
func (r *ReverseIPFetcher) Lookup(ctx context.Context, domain string) (*model.ReverseIPResult, error) {
	ips, err := net.LookupHost(domain)
	if err != nil {
		return nil, fmt.Errorf("domain resolution failed: %w", err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for domain")
	}

	ip := ips[0]

	result := &model.ReverseIPResult{
		IP: ip,
	}

	// Method 1: HackerTarget API (free tier)
	domains, err := r.queryHackerTarget(ctx, ip)
	if err == nil && len(domains) > 0 {
		result.DomainsFound = domains
		result.TotalDomains = len(domains)
		result.Source = "hackertarget"
		return result, nil
	}

	// Method 2: ViewDNS API (requires API key)
	if r.cfg.ViewDNSAPIKey != "" {
		domains, err := r.queryViewDNS(ctx, domain, ip)
		if err == nil && len(domains) > 0 {
			result.DomainsFound = domains
			result.TotalDomains = len(domains)
			result.Source = "viewdns"
			return result, nil
		}
	}

	// Method 3: DNS PTR records (always available but limited)
	ptrDomains, _ := r.queryPTR(ctx, ip)
	if len(ptrDomains) > 0 {
		result.DomainsFound = ptrDomains
		result.TotalDomains = len(ptrDomains)
		result.Source = "dns_ptr"
	}

	if len(result.DomainsFound) == 0 {
		return result, fmt.Errorf("no reverse IP methods returned results")
	}

	return result, nil
}

func (r *ReverseIPFetcher) queryHackerTarget(ctx context.Context, ip string) ([]string, error) {
	url := fmt.Sprintf("%s/?q=%s", r.cfg.HackerTargetBaseURL, ip)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hackertarget API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	text := string(body)
	if strings.Contains(text, "error") || strings.Contains(text, "No records") {
		return nil, fmt.Errorf("hackertarget found no records")
	}

	lines := strings.Split(strings.TrimSpace(text), "\n")
	domains := make([]string, 0, len(lines))
	for _, line := range lines {
		domain := strings.TrimSpace(line)
		if domain != "" && domain != ip {
			domains = append(domains, domain)
		}
	}

	return domains, nil
}

type viewdnsResponse struct {
	Query struct {
		Host string `json:"host"`
		IP   string `json:"ip"`
	} `json:"query"`
	Response struct {
		DomainCount int `json:"domain_count"`
		Domains     []struct {
			Domain       string `json:"domain"`
			LastResolved string `json:"last_resolved"`
		} `json:"domains"`
	} `json:"response"`
}

func (r *ReverseIPFetcher) queryViewDNS(ctx context.Context, domain, ip string) ([]string, error) {
	url := fmt.Sprintf("https://api.viewdns.info/reverseip/?host=%s&apikey=%s&output=json",
		domain, r.cfg.ViewDNSAPIKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var vd viewdnsResponse
	if err := json.Unmarshal(body, &vd); err != nil {
		return nil, err
	}

	domains := make([]string, 0, len(vd.Response.Domains))
	for _, d := range vd.Response.Domains {
		domains = append(domains, d.Domain)
	}

	return domains, nil
}

func (r *ReverseIPFetcher) queryPTR(ctx context.Context, ip string) ([]string, error) {
	names, err := net.LookupAddr(ip)
	if err != nil {
		return nil, err
	}

	domains := make([]string, len(names))
	for i, name := range names {
		domains[i] = strings.TrimSuffix(name, ".")
	}

	return domains, nil
}
