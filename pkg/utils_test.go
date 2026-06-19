package utils

import (
	"testing"
)

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"https scheme present", "https://example.com", "https://example.com", false},
		{"http scheme present", "http://example.com/path", "http://example.com/path", false},
		{"no scheme", "example.com", "https://example.com", false},
		{"no scheme with path", "example.com/login", "https://example.com/login", false},
		{"uppercase scheme and host", "HTTPS://EXAMPLE.COM", "https://example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeURL(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("NormalizeURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("NormalizeURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://example.com/path", "example.com"},
		{"https://sub.example.co.uk/path", "sub.example.co.uk"},
		{"https://192.168.1.1/path", "192.168.1.1"},
		{"http://localhost:8080/test", "localhost"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ExtractDomain(tt.input)
			if got != tt.want {
				t.Errorf("ExtractDomain() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUsesIP(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"https://192.168.1.1/login", true},
		{"http://10.0.0.1/admin", true},
		{"https://example.com", false},
		{"https://1.2.3.4", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := UsesIP(tt.input)
			if got != tt.want {
				t.Errorf("UsesIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsSuspiciousTLD(t *testing.T) {
	tests := []struct {
		domain string
		want   bool
	}{
		{"example.tk", true},
		{"test.xyz", true},
		{"malware.top", true},
		{"normal.com", false},
		{"site.org", false},
		{"something.net", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := IsSuspiciousTLD(tt.domain)
			if got != tt.want {
				t.Errorf("IsSuspiciousTLD() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractTLD(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{"example.com", ".com"},
		{"sub.example.org", ".org"},
		{"test", ""},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := ExtractTLD(tt.domain)
			if got != tt.want {
				t.Errorf("ExtractTLD() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestURLDepth(t *testing.T) {
	tests := []struct {
		url  string
		want int
	}{
		{"https://example.com", 0},
		{"https://example.com/a", 1},
		{"https://example.com/a/b/c", 3},
		{"https://example.com/a/b/c/", 3},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := URLDepth(tt.url)
			if got != tt.want {
				t.Errorf("URLDepth() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasAtSymbol(t *testing.T) {
	if !HasAtSymbol("https://user@example.com") {
		t.Error("HasAtSymbol() should detect @ in URL")
	}
	if HasAtSymbol("https://example.com") {
		t.Error("HasAtSymbol() should return false for clean URL")
	}
}

func TestHasDoubleSlashInPath(t *testing.T) {
	if !HasDoubleSlashInPath("https://example.com/https://evil.com") {
		t.Error("HasDoubleSlashInPath() should detect // in path")
	}
	if HasDoubleSlashInPath("https://example.com/normal") {
		t.Error("HasDoubleSlashInPath() should return false for clean path")
	}
}

func TestDomainEntropy(t *testing.T) {
	// Random-looking domain should have higher entropy than normal domain
	randomEntropy := DomainEntropy("frsttlrrrkmpnyaabsvrrrrsonnnn.xyz")
	normalEntropy := DomainEntropy("example.com")

	if randomEntropy <= normalEntropy {
		t.Errorf("Random domain entropy (%.2f) should exceed normal domain entropy (%.2f)",
			randomEntropy, normalEntropy)
	}

	if DomainEntropy("aaaaa.com") > 1.0 {
		t.Error("Entropy of repetitive domain should be very low")
	}
}

func TestConsonantVowelRatio(t *testing.T) {
	// All-consonant domain should have high ratio
	if cv := ConsonantVowelRatio("frsttlrrrkmpn.com"); cv < 5.0 {
		t.Errorf("All-consonant domain CV ratio should be high, got %.2f", cv)
	}
}

func TestDigitRatio(t *testing.T) {
	if dr := DigitRatio("t74909303.click"); dr <= 0.3 {
		t.Errorf("Digit-heavy domain should have high ratio, got %.2f", dr)
	}
	if dr := DigitRatio("example.com"); dr != 0 {
		t.Errorf("Domain with no digits should have ratio 0, got %.2f", dr)
	}
}
