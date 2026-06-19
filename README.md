# Aegis — Phishing Detection API

A high-performance URL threat classification API built with Go. Fetches page content, extracts forensic features, performs multi-layer heuristic scoring, and leverages LLM analysis (DeepSeek) for accurate threat labeling.

---

## Features

- **Multi-layer detection pipeline**: Heuristic pre-analysis + LLM-based classification
- **Multi-label classification**: 16 threat categories across 5 groups (phishing, malware, harmful content, parked domains, safe)
- **Domain forensic analysis**: Shannon entropy, consonant/vowel ratio, digit ratio, random pattern detection, typosquatting checks
- **WHOIS integration**: Domain age, registrar, free hosting detection
- **Reverse IP lookup**: Discover co-hosted domains on the same IP (sweep mode)
- **SSL/TLS analysis**: Certificate validity, self-signed detection, expiration tracking
- **Resilient fetching**: HTTPS with TLS validation, insecure fallback for suspicious certs, HTTP downgrade
- **Turkish phishing keyword detection**: Specialized detection for Turkish financial/government phishing campaigns
- **Few-shot AI prompting**: LLM prompt includes real phishing examples for improved accuracy
- **Pre-analysis override**: Heuristic engine can override AI decisions for high-confidence cases
- **Extensible AI provider interface**: Add new LLM providers (Gemini, OpenAI) by implementing one interface

---

---

## LLM Provider Comparison

Aegis uses an AI provider interface, making it straightforward to switch between LLM backends. The default implementation uses **DeepSeek**, selected for its optimal price-to-performance ratio for threat classification tasks.

### Why DeepSeek?

| Factor | DeepSeek | OpenAI (GPT-4o) | Google (Gemini) |
|--------|----------|-----------------|-----------------|
| **Cost per 1M input tokens** | $0.27 | $2.50 | $0.35 |
| **Cost per 1M output tokens** | $1.10 | $10.00 | $1.05 |
| **Avg response time** | ~2-5 sec | ~3-8 sec | ~2-5 sec |
| **Classification accuracy** | 92-98% | 94-98% | 90-96% |
| **API compatibility** | OpenAI-compatible | Native | Native |
| **Rate limits (free tier)** | None (pay-go) | Tiered | 15 RPM (free) |
| **Turkish language support** | Excellent | Very good | Good |
| **JSON mode reliability** | High | High | Medium |

**Cost estimate** — 10,000 URL checks per month:
- DeepSeek: ~$3-8/month
- OpenAI GPT-4o: ~$30-80/month
- Gemini 1.5 Flash: ~$2-5/month

DeepSeek offers the best balance: OpenAI-compatible API (zero migration effort), excellent Turkish language understanding for detecting Turkish phishing campaigns, and pricing roughly 10x cheaper than GPT-4o for comparable quality.

### Switching Providers

The `AIProvider` interface in `internal/ai/provider.go` requires only two methods:

```go
type AIProvider interface {
    Analyze(ctx context.Context, url string, features *model.PageFeatures) (*model.AIAnalysis, error)
    Name() string
}
```

**Using Gemini:**
```go
// internal/ai/gemini.go
type geminiProvider struct { cfg *config.Config }
func NewGemini(cfg *config.Config) AIProvider { ... }

// main.go
geminiAI := ai.NewGemini(cfg)
```

**Using OpenAI:**
```go
// Change DEEPSEEK_BASE_URL to https://api.openai.com/v1
// and DEEPSEEK_MODEL to gpt-4o
// The DeepSeek provider already uses OpenAI-compatible API format
```

The system prompt and few-shot examples in `deepseek.go` are provider-agnostic and work across all major LLMs.

---

## Architecture

```
URL Input
  |
  +--> [1] WHOIS Lookup (domain age, registrar, free hosting)
  |
  +--> [2] HTTP Fetch (HTML + SSL certificate)
  |     TLS validated -> insecure fallback -> HTTP downgrade
  |
  +--> [3] Feature Extraction
  |     Page meta (title, description, favicon)
  |     Form analysis (password fields, external actions, hidden inputs)
  |     Link analysis (internal/external ratio, unique domains)
  |     Script/iframe enumeration
  |     Visible text extraction
  |     Domain entropy, CV ratio, digit ratio, suspicion score
  |
  +--> [4] Pre-Analysis Scoring (6-layer heuristic)
  |     Hard rules (domain patterns, free hosting + keywords)
  |     Domain structure, TLD, WHOIS, SSL, content layers
  |     Output: 0-100 score + recommendation
  |
  +--> [5] AI Analysis (DeepSeek LLM)
  |     Few-shot prompting with labeled examples
  |     Multi-label classification output
  |
  +--> [6] Decision Fusion
        Pre-analyzer override for high-confidence cases
        Final: is_threat, label, category, confidence, risk_level
```

## API Endpoints

### `POST /api/v1/check`

Analyze a single URL for threats.

**Request:**
```json
{
  "url": "https://suspicious-site.xyz/login"
}
```

**Response:**
```json
{
  "url": "https://suspicious-site.xyz/login",
  "is_threat": true,
  "label": "banking_phishing",
  "category": "phishing",
  "confidence": 0.92,
  "analysis": {
    "is_threat": true,
    "label": "banking_phishing",
    "category": "phishing",
    "confidence": 0.92,
    "risk_level": "high",
    "reasons": ["Domain only 2 days old", "Self-signed SSL certificate", "Free hosting subdomain"],
    "indicators": ["brand_new_domain", "self_signed_ssl", "free_hosting"],
    "domain_flags": {
      "suspicious_tld": true,
      "typosquatting": false,
      "recently_registered": true,
      "imitates_brand": "",
      "uses_free_hosting": true,
      "url_length_excessive": false
    }
  },
  "features": {
    "title": "Bank Login",
    "has_password_field": true,
    "domain_entropy": 3.12,
    "domain_suspicion_score": 55,
    "whois_info": {
      "domain_age_days": 2,
      "is_newly_registered": true,
      "is_free_hosting": true
    }
  },
  "pre_analysis": {
    "total_score": 80,
    "recommendation": "likely_phishing",
    "flags": ["hard_rule_free_hosting_plus_keyword_plus_number"]
  }
}
```

### `POST /api/v1/sweep`

Check a URL and scan all domains on the same IP.

**Request:**
```json
{
  "url": "https://known-phishing.xyz",
  "scan_siblings": true
}
```

### `GET /api/v1/health`

Health check endpoint.

## Threat Labels

| Category | Labels |
|----------|--------|
| `phishing` | `banking_phishing`, `social_media_phishing`, `government_phishing`, `ecommerce_scam`, `investment_scam`, `credential_harvesting`, `generic_phishing` |
| `malware` | `malware`, `cryptominer` |
| `harmful_content` | `gambling`, `adult_content`, `fake_news`, `spam` |
| `parked` | `parked_domain`, `defaced` |
| `safe` | `safe` |

## Risk Levels

| Level | Description |
|-------|-------------|
| `safe` | No threat detected |
| `low` | Minor suspicious indicators |
| `medium` | Several suspicious indicators, needs review |
| `high` | Strong phishing/threat indicators |
| `critical` | Confirmed threat, multiple critical indicators |

## Quick Start

### Prerequisites

- Go 1.21 or later
- DeepSeek API key ([platform.deepseek.com](https://platform.deepseek.com))

### Installation

```bash
git clone https://github.com/user/aegis.git
cd aegis
cp .env.example .env
# Edit .env and add your DEEPSEEK_API_KEY=sk-xxx
```

### Run

```bash
go run main.go
```

Server starts on `http://localhost:8080`.

### Test

```bash
# Unit tests
go test ./...

# Check a URL
curl -X POST http://localhost:8080/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'

# Sweep mode (reverse IP + bulk scan)
curl -X POST http://localhost:8080/api/v1/sweep \
  -H "Content-Type: application/json" \
  -d '{"url":"https://suspicious.xyz","scan_siblings":true}'
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Server port |
| `LOG_LEVEL` | `info` | debug, info, warn, error |
| `DEEPSEEK_API_KEY` | — | DeepSeek API key (required) |
| `DEEPSEEK_MODEL` | `deepseek-chat` | Model name |
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com/v1` | API base URL |
| `FETCH_TIMEOUT_SEC` | `15` | HTTP fetch timeout |
| `MAX_BODY_SIZE_MB` | `5` | Max page body size |
| `VIEWDNS_API_KEY` | — | ViewDNS API key (optional, for reverse IP) |
| `MAX_SIBLING_SCANS` | `20` | Max domains to scan in sweep mode |
| `SWEEP_CONCURRENCY` | `5` | Concurrent scans in sweep mode |

## Project Structure

```
aegis/
  main.go                       Entry point, HTTP server
  config/config.go              Environment-based configuration
  pkg/utils.go                  URL normalization, domain analysis utilities
  internal/
    model/model.go              All data types (request, response, analysis)
    fetcher/
      http.go                   HTTP page fetching with TLS fallback
      reverse_ip.go             Reverse IP lookup (HackerTarget, ViewDNS, DNS PTR)
      whois.go                  WHOIS domain lookup
    parser/parser.go            HTML parsing and feature extraction (goquery)
    analyzer/heuristic.go       Multi-layer pre-AI heuristic scoring
    ai/
      provider.go               AI provider interface
      deepseek.go               DeepSeek LLM integration
    handler/
      check.go                  POST /api/v1/check
      sweep.go                  POST /api/v1/sweep
      health.go                 GET /api/v1/health
```

## Extending

### Adding a new AI provider

```go
// Implement the AIProvider interface in internal/ai/
type AIProvider interface {
    Analyze(ctx context.Context, url string, features *model.PageFeatures) (*model.AIAnalysis, error)
    Name() string
}

// Register in main.go
geminiAI := ai.NewGemini(cfg)
checkHandler := handler.NewCheckHandler(f, whoisFetcher, p, preAnalyzer, geminiAI)
```

### Adding a new threat label

Add the label to `model.ValidLabels` and update the AI system prompt in `deepseek.go`.

## License

MIT — See [LICENSE](LICENSE) for details.

---

# Aegis — Oltalama Tespit API'si (TR)

Go ile yazilmis yuksek performansli URL tehdit siniflandirma API'si. Sayfa icerigini ceker, adli analiz ozellikleri cikarir, cok katmanli sezgisel skorlama yapar ve dogru tehdit etiketlemesi icin LLM (DeepSeek) analizi kullanir.

## Ozellikler

- **Cok katmanli tespit**: Sezgisel on-analiz + LLM tabanli siniflandirma
- **Coklu etiket siniflandirmasi**: 5 grupta 16 tehdit kategorisi
- **Domain adli analizi**: Shannon entropisi, sessiz/sesli harf orani, rakam orani, rastgele desen tespiti, typosquatting kontrolleri
- **WHOIS entegrasyonu**: Domain yasi, registrar, ucretsiz hosting tespiti
- **Ters IP sorgulama**: Ayni IP'deki diger domain'leri bulma ve tarama
- **SSL/TLS analizi**: Sertifika gecerliligi, self-signed tespiti, son kullanim takibi
- **Dayanikli fetch**: TLS dogrulamali HTTPS, supheli sertifikalar icin insecure fallback, HTTP'ye dusme
- **Turkce oltalama anahtar kelime tespiti**: Turk finans/kurumsal oltalama kampanyalari icin ozel tespit
- **Few-shot AI prompting**: LLM prompt'u dogrulugu artirmak icin gercek oltalama ornekleri icerir
- **On-analiz override**: Yuksek guvenli durumlarda sezgisel motor AI kararini gecersiz kilabilir
- **Genisletilebilir AI saglayici arayuzu**: Yeni LLM saglayicilari eklemek kolay

---

## LLM Saglayici Karsilastirmasi (TR)

Aegis, AI saglayici arabirimi sayesinde farkli LLM'ler arasinda kolayca gecis yapabilir. Varsayilan olarak **DeepSeek** kullanilir — tehdit siniflandirmasi icin en iyi fiyat/performans oranini sundugu icin secilmistir.

### Neden DeepSeek?

| Faktor | DeepSeek | OpenAI (GPT-4o) | Google (Gemini) |
|--------|----------|-----------------|-----------------|
| **1M giris token maliyeti** | $0.27 | $2.50 | $0.35 |
| **1M cikis token maliyeti** | $1.10 | $10.00 | $1.05 |
| **Ort. yanit suresi** | ~2-5 sn | ~3-8 sn | ~2-5 sn |
| **Siniflandirma dogrulugu** | %92-98 | %94-98 | %90-96 |
| **API uyumlulugu** | OpenAI-uyumlu | Native | Native |
| **Turkce dil destegi** | Mukemmel | Cok iyi | Iyi |
| **JSON modu guvenilirligi** | Yuksek | Yuksek | Orta |

**Maliyet tahmini** — Aylik 10.000 URL kontrolu:
- DeepSeek: ~$3-8/ay
- OpenAI GPT-4o: ~$30-80/ay
- Gemini 1.5 Flash: ~$2-5/ay

DeepSeek en iyi dengeyi sunar: OpenAI-uyumlu API (sifir gecis maliyeti), Turkce oltalama kampanyalarini tespitte mukemmel dil destegi ve GPT-4o'ya kiyasla yaklasik 10 kat daha ucuz.

### Saglayici Degistirme

```go
// OpenAI'a gecmek icin .env dosyasinda:
DEEPSEEK_BASE_URL=https://api.openai.com/v1
DEEPSEEK_MODEL=gpt-4o
DEEPSEEK_API_KEY=sk-openai-key

// Gemini eklemek icin internal/ai/gemini.go olusturup
// AIProvider interface'ini implemente edin.
```

---

## Hizli Baslangic

```bash
git clone https://github.com/user/aegis.git
cd aegis
cp .env.example .env
# .env dosyasini duzenle: DEEPSEEK_API_KEY=sk-xxx
go run main.go
```

## Tehdit Etiketleri

| Kategori | Etiketler |
|----------|-----------|
| `phishing` | `banking_phishing`, `social_media_phishing`, `government_phishing`, `ecommerce_scam`, `investment_scam`, `credential_harvesting`, `generic_phishing` |
| `malware` | `malware`, `cryptominer` |
| `harmful_content` | `gambling`, `adult_content`, `fake_news`, `spam` |
| `parked` | `parked_domain`, `defaced` |
| `safe` | `safe` |

## Risk Seviyeleri

| Seviye | Aciklama |
|--------|----------|
| `safe` | Tehdit tespit edilmedi |
| `low` | Kucuk supheli gostergeler |
| `medium` | Birkac supheli gosterge, incelenmeli |
| `high` | Guclu oltalama/tehdit gostergeleri |
| `critical` | Kesinlesmis tehdit, kritik gostergeler |

## Lisans

MIT — Detaylar icin [LICENSE](LICENSE) dosyasina bakin.
