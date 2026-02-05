# XSSpect - XSS Vulnerability Scanner

**A browser-verified XSS detection tool with 700+ built-in payloads.**

XSSpect is a CLI scanner for detecting reflected XSS vulnerabilities. It uses browser verification to confirm if payloads actually execute, reducing false positives.

![Tech Stack](https://img.shields.io/badge/Stack-Go%20%7C%20Selenium%20%7C%20ChromeDriver-blue)
![Version](https://img.shields.io/badge/version-1.0-green)

---

## Team Details
* **Team Name:** TEAM MARCO
* **Leader:** Siddharth Swami
* **Member:** Ayush Shankarpure
* **Member:** Chinmay Kulkarni

## Problem Statement
Manual XSS testing is time-consuming and error-prone. Automated tools often generate high false positive rates with no real execution verification.

## The Solution
XSSpect uses Selenium + ChromeDriver to verify if XSS payloads actually execute in a real browser, providing confirmed vulnerabilities instead of guesswork.

---

## Key Features

* **700+ Built-in Payloads**: Comprehensive payload library covering modern XSS vectors.
* **Browser Verification**: Launches headless Chrome to verify if alert/confirm/prompt actually triggers.
* **CSV Reports**: Structured reports with timestamp, severity, and verification status.
* **Severity Classification**: Critical, High, Medium, Low, Info levels.

---

## Tech Stack

| Component | Technology | Purpose |
| :--- | :--- | :--- |
| Core Engine | Go 1.21+ | High-performance scanning |
| Browser Automation | Selenium WebDriver | Real browser verification |
| Driver | ChromeDriver | Headless Chrome control |
| HTTP Client | net/http | Request handling with retry logic |
| Platform | Linux/Ubuntu | CLI-based tool |

---

## Architecture Flow

1. **Input Validation** → Validates target URL, method, parameters
2. **Payload Loading** → Loads 700+ XSS payloads
3. **Payload Injection** → Injects payloads into target parameters
4. **HTTP Request** → Sends requests with retry logic
5. **Static Analysis** → Checks response for payload reflection
6. **Browser Verification** → Launches Chrome to verify execution
7. **Report Generation** → Exports CSV report

---

## Installation & Setup

### Prerequisites
- Ubuntu/Linux
- Go 1.21+ ([Install Go](https://go.dev/doc/install))
- ChromeDriver

```bash
# Install ChromeDriver
sudo apt-get update
sudo apt-get install chromium-browser chromium-chromedriver
```

### Build XSSpect

```bash
git clone https://github.com/siddharthswami23/gdg-hack2skill.git
cd gdg-hack2skill/XSSpect
go build -o xsspect
```

---

## Usage

### Basic Syntax

```bash
./xsspect --url <target-url> --params <param1,param2> [options]
```

### Key Options

| Argument | Description |
| :--- | :--- |
| `--url` | Target URL (required) |
| `--params` | Comma-separated parameter names to test (required) |
| `--method` | HTTP method (default: GET) |
| `--browser-verify` | Verify XSS execution in browser |
| `--report` | Generate CSV report |
| `--stop-on-hit` | Stop after first XSS found |
| `--custom-payload` | Use custom payload |
| `--payload-file` | Path to custom payload file |

### Examples

**Basic Scan:**
```bash
./xsspect --url https://example.com/search --params q
```

**With Browser Verification:**
```bash
./xsspect --url https://example.com/search --params q --browser-verify
```

**Generate Report:**
```bash
./xsspect --url https://example.com/search --params q,name --browser-verify --report
```

**Custom Payload:**
```bash
./xsspect --url https://example.com/search --params q --custom-payload "<img src=x onerror=alert(1)>"
```

---

## Output Interpretation

### 🔴 Verified XSS
```
[+++] VERIFIED XSS (Executed in Browser!)
```
✅ XSS confirmed - payload executed in Chrome.

### 🟠 RAW XSS
```
[+] RAW XSS FOUND (Static Analysis)
```
⚠️ Payload reflected but not browser-verified.

### 🟡 Escaped
```
[~] Escaped reflection
```
ℹ️ Payload HTML-encoded, not exploitable.

### ⚪ No Reflection
```
[-] No reflection
```
✅ Payload not found in response.

---

## CSV Report Structure

| Field | Description |
| :--- | :--- |
| Timestamp | Scan completion time |
| Target_URL | Scanned URL |
| HTTP_Method | GET/POST/PUT |
| Parameter | Tested parameter |
| Payload | XSS payload used |
| Reflection_Type | RAW / ESCAPED / NO_REFLECTION |
| Browser_Verified | Yes/No |
| XSS_Event_Type | alert / confirm / prompt |
| Severity | Critical / High / Medium / Low / Info |

### Severity Levels
- **Critical**: Browser-verified XSS
- **High**: RAW XSS (not browser-verified)
- **Medium**: Escaped reflection
- **Info**: No reflection

---

## Troubleshooting

**ChromeDriver Not Found:**
```bash
sudo apt-get install chromium-chromedriver
```

**Browser Permission Denied:**
```bash
sudo apt-get install chromium-browser
chmod +x /usr/bin/chromedriver
```

---

**Made with ❤️ by Team MARCO for GDG Hack2Skill 2026**
