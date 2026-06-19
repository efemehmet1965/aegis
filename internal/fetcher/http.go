package fetcher

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"aegis-phishing/config"
	"aegis-phishing/internal/model"
)

// FetchResult holds the outcome of a page fetch operation.
type FetchResult struct {
	HTML        string
	FinalURL    string
	StatusCode  int
	ContentType string
	SSLInfo     *model.SSLInfo
	FetchError  string // non-empty when the fetch encountered connection errors
}

// Fetcher retrieves page content and SSL certificate information from URLs.
type Fetcher struct {
	cfg            *config.Config
	httpClient     *http.Client // standard TLS verification
	insecureClient *http.Client // relaxed TLS verification for suspicious certificates
}

// NewFetcher creates a Fetcher with dual HTTP clients: one with full TLS
// verification and one with relaxed verification for phishing sites that
// commonly use invalid or self-signed certificates.
func NewFetcher(cfg *config.Config) *Fetcher {
	normalTransport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
		MaxIdleConns:    10,
		IdleConnTimeout: 30 * time.Second,
	}

	insecureTransport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxIdleConns:    10,
		IdleConnTimeout: 30 * time.Second,
	}

	createClient := func(transport *http.Transport) *http.Client {
		return &http.Client{
			Timeout:   cfg.FetchTimeout,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects (%d)", len(via))
				}
				return nil
			},
		}
	}

	return &Fetcher{
		cfg:            cfg,
		httpClient:     createClient(normalTransport),
		insecureClient: createClient(insecureTransport),
	}
}

// Fetch attempts to retrieve the page at rawURL using a cascade of strategies:
//  1. HTTPS with strict TLS verification
//  2. HTTPS with relaxed TLS verification (captures self-signed / invalid certs)
//  3. HTTP downgrade (when HTTPS fails entirely)
//
// Returns a partial FetchResult even when all strategies fail, with SSLInfo
// populated from connection error details where possible.
func (f *Fetcher) Fetch(ctx context.Context, rawURL string) (*FetchResult, error) {
	var lastErr error

	// Strategy 1: Standard HTTPS
	result, err := f.tryFetch(ctx, rawURL, f.httpClient)
	if err == nil {
		return result, nil
	}
	lastErr = err

	// Strategy 2: Insecure TLS (common for phishing sites with bad certs)
	if isTLSError(err) {
		result, err := f.tryFetch(ctx, rawURL, f.insecureClient)
		if err == nil {
			if result.SSLInfo != nil {
				result.SSLInfo.Valid = false
				result.SSLInfo.IsSelfSigned = true
				result.FetchError = "TLS verification failed (invalid/self-signed certificate) — potential phishing indicator"
			}
			return result, nil
		}
		lastErr = err
	}

	// Strategy 3: HTTP downgrade
	if strings.HasPrefix(rawURL, "https://") {
		httpURL := strings.Replace(rawURL, "https://", "http://", 1)
		result, err := f.tryFetch(ctx, httpURL, f.httpClient)
		if err == nil {
			if result.SSLInfo != nil {
				result.SSLInfo.Valid = false
			}
			return result, nil
		}
		lastErr = err
	}

	// All strategies exhausted — return partial result with SSL error info
	return &FetchResult{
		FinalURL:   rawURL,
		SSLInfo:    extractSSLError(rawURL, lastErr),
		FetchError: lastErr.Error(),
	}, fmt.Errorf("all fetch strategies failed: %w", lastErr)
}

func (f *Fetcher) tryFetch(ctx context.Context, rawURL string, client *http.Client) (*FetchResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("request creation failed: %w", err)
	}

	req.Header.Set("User-Agent", f.cfg.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	limitedReader := io.LimitReader(resp.Body, f.cfg.MaxBodySize)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("body read failed: %w", err)
	}

	result := &FetchResult{
		HTML:        string(body),
		FinalURL:    resp.Request.URL.String(),
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
	}

	result.SSLInfo = extractSSLInfo(resp, rawURL)

	return result, nil
}

func isTLSError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "tls:") ||
		strings.Contains(errStr, "x509:") ||
		strings.Contains(errStr, "certificate")
}

func extractSSLError(rawURL string, err error) *model.SSLInfo {
	info := &model.SSLInfo{Valid: true}

	parsed, _ := url.Parse(rawURL)
	if parsed == nil || parsed.Scheme != "https" {
		info.Valid = false
		return info
	}

	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "tls:") || strings.Contains(errStr, "x509:") || strings.Contains(errStr, "certificate") {
			info.Valid = false
			info.Issuer = "TLS ERROR: " + errStr
			info.IsSelfSigned = strings.Contains(errStr, "self-signed") || strings.Contains(errStr, "unknown authority")
		}
	}

	return info
}

func extractSSLInfo(resp *http.Response, rawURL string) *model.SSLInfo {
	info := &model.SSLInfo{Valid: true}

	parsed, _ := url.Parse(rawURL)
	if parsed == nil {
		return info
	}

	if parsed.Scheme != "https" {
		info.Valid = false
		return info
	}

	if resp.TLS == nil {
		return info
	}

	if len(resp.TLS.PeerCertificates) == 0 {
		info.Valid = false
		return info
	}

	cert := resp.TLS.PeerCertificates[0]

	info.Issuer = cert.Issuer.String()
	info.Subject = cert.Subject.String()
	info.NotBefore = cert.NotBefore
	info.NotAfter = cert.NotAfter
	info.DNSNames = cert.DNSNames
	info.Version = cert.Version

	info.DaysRemaining = int(time.Until(cert.NotAfter).Hours() / 24)
	info.IsExpired = info.DaysRemaining < 0
	info.IsSelfSigned = cert.Issuer.String() == cert.Subject.String()

	return info
}

// IsHTMLContent checks whether the Content-Type header indicates an HTML response.
func IsHTMLContent(contentType string) bool {
	return strings.Contains(contentType, "text/html") ||
		strings.Contains(contentType, "application/xhtml")
}
