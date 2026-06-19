package parser

import (
	"regexp"
	"strings"
	"unicode"

	"aegis-phishing/internal/model"
	"aegis-phishing/pkg"

	"github.com/PuerkitoBio/goquery"
)

var (
	multiSpace = regexp.MustCompile(`\s+`)

	// Well-known brand names used for typosquatting detection.
	commonBrands = []string{
		"paypal", "facebook", "google", "microsoft", "apple", "amazon",
		"netflix", "instagram", "twitter", "whatsapp", "linkedin", "dropbox",
		"adobe", "dhl", "fedex", "ups", "chase", "wellsfargo",
		"citibank", "hsbc", "barclays", "deutsche", "santander", "bbva",
		"steam", "epic", "roblox", "discord", "telegram", "spotify",
		"ziraat", "garanti", "isbank", "akbank", "yapikredi", "vakifbank",
		"halkbank", "denizbank", "teb", "ing", "ptt",
	}
)

// Parser extracts forensic features from HTML content and URL structure
// for threat classification.
type Parser struct {
	brands map[string]bool
}

// NewParser creates a new HTML feature extractor.
func NewParser() *Parser {
	brands := make(map[string]bool, len(commonBrands))
	for _, b := range commonBrands {
		brands[b] = true
	}
	return &Parser{brands: brands}
}

// Extract processes HTML content and URL structure, populating a PageFeatures
// struct with all forensic indicators needed for threat analysis.
func (p *Parser) Extract(htmlContent, pageURL string, sslInfo *model.SSLInfo) *model.PageFeatures {
	features := &model.PageFeatures{}

	p.extractURLFeatures(pageURL, features)

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		return features
	}

	p.extractMeta(doc, features)
	p.extractForms(doc, pageURL, features)
	p.extractLinks(doc, pageURL, features)

	// Must run before extractVisibleText which removes script/style nodes
	p.extractScripts(doc, features)

	p.extractVisibleText(doc, features)

	if sslInfo != nil {
		features.SSLInfo = sslInfo
	}

	return features
}

func (p *Parser) extractURLFeatures(rawURL string, f *model.PageFeatures) {
	f.URLUsesIP = utils.UsesIP(rawURL)

	domain := utils.ExtractDomain(rawURL)
	f.URLHasSuspiciousTLD = utils.IsSuspiciousTLD(domain)
	f.URLDepth = utils.URLDepth(rawURL)
	f.URLQueryParams = utils.QueryParamCount(rawURL)
	f.URLIsHTTPS = utils.IsHTTPS(rawURL)
	f.URLHasAtSymbol = utils.HasAtSymbol(rawURL)
	f.URLHasDoubleSlash = utils.HasDoubleSlashInPath(rawURL)

	// Domain randomness metrics
	f.DomainEntropy = utils.DomainEntropy(domain)
	f.DomainCVRatio = utils.ConsonantVowelRatio(domain)
	f.DomainDigitRatio = utils.DigitRatio(domain)
	f.DomainSuspicionScore = utils.DomainSuspicionScore(domain)
	f.DomainHasRandomPattern = utils.HasRandomPattern(domain)
	f.DomainHasRepeatedChars = utils.HasRepeatedChars(domain)
	f.DomainLength = len(utils.MainDomainPart(domain))
	f.DomainWordCount = utils.DomainWordCount(domain)
	f.HeuristicFlags = utils.HeuristicIndicators(domain)
}

func (p *Parser) extractMeta(doc *goquery.Document, f *model.PageFeatures) {
	f.Title = strings.TrimSpace(doc.Find("title").First().Text())

	f.MetaDescription, _ = doc.Find(`meta[name="description"]`).Attr("content")
	if f.MetaDescription == "" {
		f.MetaDescription, _ = doc.Find(`meta[property="og:description"]`).Attr("content")
	}

	favicon, exists := doc.Find(`link[rel="icon"]`).Attr("href")
	if !exists {
		favicon, exists = doc.Find(`link[rel="shortcut icon"]`).Attr("href")
	}
	if exists {
		f.FaviconURL = favicon
	}
}

func (p *Parser) extractForms(doc *goquery.Document, pageURL string, f *model.PageFeatures) {
	pageDomain := utils.ExtractDomain(pageURL)

	doc.Find("form").Each(func(i int, form *goquery.Selection) {
		f.HasForm = true

		action, exists := form.Attr("action")
		if exists {
			f.FormActions = append(f.FormActions, action)

			actionDomain := utils.ExtractDomain(action)
			if actionDomain != "" && actionDomain != pageDomain {
				f.FormActionExternal = true
			}
		}

		method, exists := form.Attr("method")
		if exists {
			f.FormMethods = append(f.FormMethods, strings.ToUpper(method))
		}

		form.Find("input").Each(func(j int, input *goquery.Selection) {
			inputType, _ := input.Attr("type")
			inputName, _ := input.Attr("name")

			f.InputNames = append(f.InputNames, inputName)

			if strings.ToLower(inputType) == "password" {
				f.HasPasswordField = true
			}

			if strings.ToLower(inputType) == "hidden" {
				f.HiddenInputNames = append(f.HiddenInputNames, inputName)
			}
		})
	})

	// Check for password fields even without a form element
	if !f.HasForm {
		doc.Find("input[type='password']").Each(func(i int, s *goquery.Selection) {
			f.HasPasswordField = true
		})
	}
}

func (p *Parser) extractLinks(doc *goquery.Document, pageURL string, f *model.PageFeatures) {
	pageDomain := utils.ExtractDomain(pageURL)
	domainCount := make(map[string]int)
	externalDomains := make(map[string]int)

	doc.Find("a[href]").Each(func(i int, link *goquery.Selection) {
		href, _ := link.Attr("href")
		if href == "" || strings.HasPrefix(href, "#") ||
			strings.HasPrefix(href, "javascript:") ||
			strings.HasPrefix(href, "mailto:") ||
			strings.HasPrefix(href, "tel:") {
			return
		}

		f.TotalLinks++

		linkDomain := utils.ExtractDomain(href)
		if linkDomain == "" {
			f.InternalLinks++
			domainCount[pageDomain]++
			return
		}

		domainCount[linkDomain]++

		if linkDomain == pageDomain {
			f.InternalLinks++
		} else {
			f.ExternalLinks++
			externalDomains[linkDomain]++
		}
	})

	for d := range domainCount {
		f.UniqueDomains = append(f.UniqueDomains, d)
	}
	for d := range externalDomains {
		f.ExternalDomains = append(f.ExternalDomains, d)
	}

	if f.TotalLinks > 0 {
		f.ExternalLinkRatio = float64(f.ExternalLinks) / float64(f.TotalLinks)
	}
}

func (p *Parser) extractVisibleText(doc *goquery.Document, f *model.PageFeatures) {
	// Remove non-visible elements before extracting text
	doc.Find("script, style, noscript, iframe, head").Each(func(i int, s *goquery.Selection) {
		s.Remove()
	})

	bodyText := doc.Find("body").Text()
	bodyText = multiSpace.ReplaceAllString(bodyText, " ")
	bodyText = strings.TrimSpace(bodyText)

	printableCount := 0
	for _, r := range bodyText {
		if !unicode.IsSpace(r) && unicode.IsPrint(r) {
			printableCount++
		}
	}

	if len(bodyText) > 1500 {
		bodyText = bodyText[:1500]
	}

	f.VisibleText = bodyText
	f.TextLength = printableCount
}

func (p *Parser) extractScripts(doc *goquery.Document, f *model.PageFeatures) {
	f.ScriptCount = doc.Find("script").Length()
	f.IframeCount = doc.Find("iframe").Length()

	doc.Find("script[src]").Each(func(i int, s *goquery.Selection) {
		src, _ := s.Attr("src")
		if src != "" && (strings.HasPrefix(src, "http://") ||
			strings.HasPrefix(src, "https://") ||
			strings.HasPrefix(src, "//")) {
			f.ExternalScripts++
		}
	})
}

// DetectBrandInTitle checks whether the page title contains a known brand name.
func (p *Parser) DetectBrandInTitle(title string) string {
	lower := strings.ToLower(title)
	for _, brand := range commonBrands {
		if strings.Contains(lower, brand) {
			return brand
		}
	}
	return ""
}

// DetectBrandInURL checks whether the URL contains a known brand name.
func (p *Parser) DetectBrandInURL(rawURL string) string {
	lower := strings.ToLower(rawURL)
	for _, brand := range commonBrands {
		if strings.Contains(lower, brand) {
			return brand
		}
	}
	return ""
}

// IsTypoSquatting checks whether a domain is likely typosquatting a known brand
// using prefix matching and Levenshtein distance analysis.
func (p *Parser) IsTypoSquatting(domain string) bool {
	domainLower := strings.ToLower(domain)
	parts := strings.Split(domainLower, ".")
	if len(parts) < 2 {
		return false
	}
	mainPart := parts[0]

	for _, brand := range commonBrands {
		brandLen := len(brand)
		mainLen := len(mainPart)

		if mainPart == brand {
			return false
		}

		// Brand appears within the domain
		if strings.Contains(mainPart, brand) {
			lenDiff := mainLen - brandLen
			// Brand at start with extra characters (e.g., paypal-login)
			if strings.HasPrefix(mainPart, brand) && lenDiff >= 1 {
				return true
			}
			// Brand embedded with small length difference
			if lenDiff >= 1 && lenDiff <= 4 {
				return true
			}
		}

		// Levenshtein distance for minor character variations (e.g., paypa1, goog1e)
		lenDiff := mainLen - brandLen
		if abs(lenDiff) <= 2 && levenshteinDistance(mainPart, brand) <= 2 {
			return true
		}
	}
	return false
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func levenshteinDistance(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	prev := make([]int, lb+1)
	curr := make([]int, lb+1)

	for j := 0; j <= lb; j++ {
		prev[j] = j
	}

	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min3(prev[j]+1, curr[j-1]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}

	return prev[lb]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}
