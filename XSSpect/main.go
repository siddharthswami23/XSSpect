package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"xsspect/scanner"
)

const (
	DefaultMethod = "GET"
)

// Config holds the application configuration from CLI arguments
type Config struct {
	URL              string
	Params           []string
	Method           string
	StopOnHit        bool
	ShowAll          bool
	CustomPayload    string
	PayloadFile      string
	BrowserVerify    bool
	ChromeDriverPath string
	GenerateReport   bool
	CSVOutput        string
}

func main() {
	// Parse CLI arguments
	config, err := parseArgs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Print banner
	printBanner()

	// Validate URL
	if err := scanner.ValidateURL(config.URL); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Validate HTTP method
	if err := scanner.ValidateMethod(config.Method); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Validate parameters
	if len(config.Params) == 0 {
		fmt.Fprintf(os.Stderr, "Error: No parameters specified. Use --params to specify parameters.\n")
		os.Exit(1)
	}

	// Load payloads
	var payloads []string

	// If custom payload is provided, use ONLY that payload
	if config.CustomPayload != "" {
		payloads = []string{config.CustomPayload}
		fmt.Printf("[*] Using custom payload only: %s\n", config.CustomPayload)
	} else if config.PayloadFile != "" {
		// Load payloads from custom file
		var err error
		payloads, err = loadPayloadsFromFile(config.PayloadFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading payloads from file: %v\n", err)
			os.Exit(1)
		}

		if len(payloads) == 0 {
			fmt.Fprintf(os.Stderr, "Error: Payload file is empty\n")
			os.Exit(1)
		}

		fmt.Printf("[*] Loaded payloads from custom file: %s\n", config.PayloadFile)
	} else {
		// Load built-in payloads from file
		var err error
		payloads, err = loadPayloads()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading payloads: %v\n", err)
			os.Exit(1)
		}

		if len(payloads) == 0 {
			fmt.Fprintf(os.Stderr, "Error: No payloads loaded\n")
			os.Exit(1)
		}
	}

	// Print scan info
	fmt.Printf("\n[*] Target: %s\n", config.URL)
	fmt.Printf("[*] Method: %s\n", config.Method)
	fmt.Printf("[*] Parameters: %s\n", strings.Join(config.Params, ", "))
	fmt.Printf("[*] Payloads loaded: %d\n", len(payloads))
	fmt.Printf("[*] Stop on hit: %v\n", config.StopOnHit)
	fmt.Printf("[*] Show all: %v\n", config.ShowAll)
	if config.GenerateReport {
		fmt.Printf("[*] CSV report generation: enabled\n")
		fmt.Printf("[*] CSV output: %s\n", config.CSVOutput)
	}
	fmt.Println()

	// Initialize scan summary for report generation
	scanSummary := &scanner.ScanSummary{
		TargetURL:            config.URL,
		Method:               config.Method,
		Parameters:           config.Params,
		TotalPayloads:        len(payloads),
		StartTime:            time.Now(),
		BrowserVerifyEnabled: config.BrowserVerify,
		Results:              []scanner.ScanResult{},
	}

	// Scan each parameter
	for _, param := range config.Params {
		paramResults := scanParameter(config, param, payloads)
		scanSummary.Results = append(scanSummary.Results, paramResults...)
	}

	// Update summary counts
	scanSummary.EndTime = time.Now()
	for _, result := range scanSummary.Results {
		switch result.ReflectionType {
		case scanner.RawReflection:
			scanSummary.RawCount++
			if result.BrowserVerified {
				scanSummary.VerifiedCount++
			}
		case scanner.EscapedReflection:
			scanSummary.EscapedCount++
		}
	}

	// Generate report if requested
	if config.GenerateReport {
		fmt.Println("\n[*] Generating CSV report...")

		// Save CSV report
		err = scanner.SaveCSVReport(scanSummary, config.CSVOutput)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to save CSV report: %v\n", err)
		} else {
			fmt.Printf("[+] CSV Report saved to: %s\n", config.CSVOutput)
		}

		// Sync to Google Drive using rclone
		fmt.Println("\n[*] Syncing reports to Google Drive...")
		cmd := exec.Command("rclone", "sync", "./outputs", "gdrive:csv-data")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to sync to Google Drive: %v\n", err)
			fmt.Fprintf(os.Stderr, "[!] Make sure rclone is configured (run: rclone config)\n")
		} else {
			fmt.Printf("[+] Reports synced to Google Drive: gdrive:csv-data\n")
		}
	}

	fmt.Println("\n[*] Scan completed")
}

// parseArgs parses command-line arguments and returns a Config
func parseArgs() (*Config, error) {
	config := &Config{}

	// Define flags
	url := flag.String("url", "", "Target URL (required)")
	params := flag.String("params", "", "Comma-separated parameter names (required)")
	method := flag.String("method", DefaultMethod, "HTTP method (default: GET)")
	stopOnHit := flag.Bool("stop-on-hit", false, "Stop testing a parameter after first RAW reflection")
	showAll := flag.Bool("show", false, "Show output for each payload tested (default: only triggered payloads)")
	customPayload := flag.String("custom-payload", "", "Use ONLY this custom payload (ignores built-in payloads)")
	payloadFile := flag.String("payload-file", "", "Path to custom payload file (.txt only)")
	browserVerify := flag.Bool("browser-verify", false, "Verify XSS execution in headless browser (requires ChromeDriver)")
	chromeDriver := flag.String("chrome-driver", "chromedriver", "Path to ChromeDriver executable")
	generateReport := flag.Bool("report", false, "Generate CSV report with visualizations")
	csvOutput := flag.String("csv-output", "", "Custom output file path for CSV report (default: auto-generated in outputs/)")

	// Custom usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "XSSpect - Reflected XSS Scanner\n\n")
		fmt.Fprintf(os.Stderr, "Usage: xsspect [options]\n\n")
		fmt.Fprintf(os.Stderr, "Required:\n")
		fmt.Fprintf(os.Stderr, "  --url string\n")
		fmt.Fprintf(os.Stderr, "        Target URL (must include http:// or https://)\n")
		fmt.Fprintf(os.Stderr, "  --params string\n")
		fmt.Fprintf(os.Stderr, "        Comma-separated parameter names to test\n\n")
		fmt.Fprintf(os.Stderr, "Optional:\n")
		fmt.Fprintf(os.Stderr, "  --method string\n")
		fmt.Fprintf(os.Stderr, "        HTTP method (default: GET)\n")
		fmt.Fprintf(os.Stderr, "  --stop-on-hit\n")
		fmt.Fprintf(os.Stderr, "        Stop testing a parameter after first RAW reflection\n")
		fmt.Fprintf(os.Stderr, "  --show\n")
		fmt.Fprintf(os.Stderr, "        Show output for each payload tested (default: only triggered)\n")
		fmt.Fprintf(os.Stderr, "  --custom-payload string\n")
		fmt.Fprintf(os.Stderr, "        Use ONLY this custom payload (ignores built-in payloads)\n")
		fmt.Fprintf(os.Stderr, "  --payload-file string\n")
		fmt.Fprintf(os.Stderr, "        Path to custom payload file (.txt only, shows only triggered)\n")
		fmt.Fprintf(os.Stderr, "  --browser-verify\n")
		fmt.Fprintf(os.Stderr, "        Verify XSS execution in headless browser (requires ChromeDriver)\n")
		fmt.Fprintf(os.Stderr, "  --chrome-driver string\n")
		fmt.Fprintf(os.Stderr, "        Path to ChromeDriver executable (default: chromedriver)\n")
		fmt.Fprintf(os.Stderr, "  --report\n")
		fmt.Fprintf(os.Stderr, "        Generate CSV report with visualizations (auto-timestamped in outputs/)\n")
		fmt.Fprintf(os.Stderr, "  --csv-output string\n")
		fmt.Fprintf(os.Stderr, "        Custom output file path for CSV report (default: auto-generated)\n\n")
		fmt.Fprintf(os.Stderr, "Example:\n")
		fmt.Fprintf(os.Stderr, "  xsspect --url https://example.com/search --params q,name --method GET\n")
		fmt.Fprintf(os.Stderr, "  xsspect --url https://example.com/search --params q --report\n")
		fmt.Fprintf(os.Stderr, "  xsspect --url https://example.com/search --params q --report --csv-output results.csv\n\n")
	}

	flag.Parse()

	// Validate required arguments
	if *url == "" {
		return nil, fmt.Errorf("--url is required")
	}

	if *params == "" {
		return nil, fmt.Errorf("--params is required")
	}

	// Populate config
	config.URL = *url
	config.Method = strings.ToUpper(*method)
	config.StopOnHit = *stopOnHit
	config.ShowAll = *showAll
	config.CustomPayload = *customPayload
	config.PayloadFile = *payloadFile
	config.BrowserVerify = *browserVerify
	config.ChromeDriverPath = *chromeDriver
	config.GenerateReport = *generateReport

	// Generate timestamped filename if report generation is enabled and no custom path provided
	if config.GenerateReport {
		// Create outputs directory if it doesn't exist
		if err := os.MkdirAll("outputs", 0755); err != nil {
			return nil, fmt.Errorf("failed to create outputs directory: %w", err)
		}

		// Generate timestamp-based filename
		timestamp := time.Now().Format("20060102_150405")

		if *csvOutput == "" {
			config.CSVOutput = fmt.Sprintf("outputs/xsspect_report_%s.csv", timestamp)
		} else {
			config.CSVOutput = *csvOutput
		}
	} else {
		config.CSVOutput = *csvOutput
	}

	// Validate that only one payload source is specified
	if config.CustomPayload != "" && config.PayloadFile != "" {
		return nil, fmt.Errorf("cannot use both --custom-payload and --payload-file together")
	}

	// Parse parameters
	paramList := strings.Split(*params, ",")
	for _, p := range paramList {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			config.Params = append(config.Params, trimmed)
		}
	}

	return config, nil
}

// loadPayloads loads XSS payloads from the embedded payloads file
func loadPayloads() ([]string, error) {
	// Try to read from payloads/payloads.txt relative to the executable
	file, err := os.Open("payloads/payloads.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to open payloads file: %w", err)
	}
	defer file.Close()

	var payloads []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		payloads = append(payloads, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading payloads file: %w", err)
	}

	return payloads, nil
}

// loadPayloadsFromFile loads XSS payloads from a custom user-provided file
func loadPayloadsFromFile(filePath string) ([]string, error) {
	// Validate file extension
	if !strings.HasSuffix(strings.ToLower(filePath), ".txt") {
		return nil, fmt.Errorf("only .txt files are supported")
	}

	// Try to open the file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open payload file: %w", err)
	}
	defer file.Close()

	var payloads []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		payloads = append(payloads, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading payload file: %w", err)
	}

	return payloads, nil
}

// scanParameter tests a single parameter with all payloads
func scanParameter(config *Config, param string, payloads []string) []scanner.ScanResult {
	fmt.Printf("[*] Testing param: %s\n", param)

	var results []scanner.ScanResult

	// Initialize browser verifier if enabled
	var browserVerifier *scanner.BrowserVerifier
	if config.BrowserVerify {
		browserConfig := scanner.BrowserConfig{
			ChromeDriverPath: config.ChromeDriverPath,
			Headless:         true,
		}

		bv, err := scanner.NewBrowserVerifier(browserConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to initialize browser: %v\n", err)
			fmt.Fprintf(os.Stderr, "[!] Make sure ChromeDriver is installed and in PATH\n")
			fmt.Fprintf(os.Stderr, "[!] Continuing with static analysis only...\n\n")
		} else {
			err = bv.Start()
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] Failed to start browser: %v\n", err)
				fmt.Fprintf(os.Stderr, "[!] Continuing with static analysis only...\n\n")
				browserVerifier = nil
			} else {
				browserVerifier = bv
				defer browserVerifier.Close()
				fmt.Printf("[*] Browser verification enabled (headless mode)\n\n")
			}
		}
	}

	rawHitCount := 0
	escapedHitCount := 0
	verifiedHitCount := 0

	for _, payload := range payloads {
		// Build URL with injected payload
		testURL, err := scanner.BuildRequestURL(config.URL, param, payload)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error building URL: %v\n", err)
			continue
		}

		// Send HTTP request
		reqConfig := scanner.RequestConfig{
			URL:    testURL,
			Method: config.Method,
		}

		result := scanner.SendRequest(reqConfig)

		// Handle request errors
		if result.Error != nil {
			// Only print errors that aren't just timeouts or common network issues
			// (to keep output clean)
			continue
		}

		// Analyze response
		analysis := scanner.AnalyzeResponse(result.ResponseBody, payload, param)

		// If browser verification is enabled and we found RAW reflection, verify execution
		browserVerified := false
		xssEventType := ""
		if config.BrowserVerify && browserVerifier != nil && analysis.Type == scanner.RawReflection {
			detected, eventType, err := browserVerifier.VerifyWithRetry(testURL, 1)
			if err != nil {
				// Verification failed, but we still report it as RAW (static analysis found it)
				fmt.Printf("[!] Browser verification failed: %v\n", err)
			} else if detected {
				browserVerified = true
				xssEventType = eventType
				verifiedHitCount++
			}
		}

		// Store result for report generation
		scanResult := scanner.ScanResult{
			Parameter:       param,
			Payload:         payload,
			ReflectionType:  analysis.Type,
			BrowserVerified: browserVerified,
			XSSEventType:    xssEventType,
		}
		results = append(results, scanResult)

		// Print results based on reflection type
		switch analysis.Type {
		case scanner.RawReflection:
			rawHitCount++

			// Print different message based on browser verification
			if config.BrowserVerify && browserVerified {
				fmt.Printf("\n[+++] VERIFIED XSS (Executed in Browser!)\n")
				fmt.Printf("    Param: %s\n", param)
				fmt.Printf("    Payload: %s\n", payload)
				fmt.Printf("    Event Type: %s()\n", xssEventType)
				fmt.Println()
			} else if config.BrowserVerify && !browserVerified {
				fmt.Printf("\n[+] RAW XSS FOUND (Static Analysis - Not Verified in Browser)\n")
				fmt.Printf("    Param: %s\n", param)
				fmt.Printf("    Payload: %s\n", payload)
				fmt.Println()
			} else {
				fmt.Printf("\n[+] RAW XSS FOUND\n")
				fmt.Printf("    Param: %s\n", param)
				fmt.Printf("    Payload: %s\n", payload)
				fmt.Println()
			}

			// Stop testing this parameter if --stop-on-hit is enabled
			if config.StopOnHit {
				fmt.Printf("[*] Stopping tests for param '%s' (--stop-on-hit enabled)\n\n", param)
				return results
			}

		case scanner.EscapedReflection:
			escapedHitCount++
			// Only show escaped reflections if --show flag is enabled
			if config.ShowAll {
				fmt.Printf("\n[~] Escaped reflection\n")
				fmt.Printf("    Param: %s\n", param)
				fmt.Printf("    Payload: %s\n", payload)
				fmt.Println()
			}

		case scanner.NoReflection:
			// Show all payloads if --show flag is enabled
			if config.ShowAll {
				fmt.Printf("[-] No reflection\n")
				fmt.Printf("    Param: %s\n", param)
				fmt.Printf("    Payload: %s\n", payload)
				fmt.Println()
			}
		}
	}

	// Print summary for this parameter
	if rawHitCount == 0 && escapedHitCount == 0 {
		fmt.Printf("[-] No reflections found for param: %s\n\n", param)
	} else {
		if config.BrowserVerify && verifiedHitCount > 0 {
			fmt.Printf("[*] Summary for param '%s': %d raw (%d verified in browser), %d escaped\n\n",
				param, rawHitCount, verifiedHitCount, escapedHitCount)
		} else {
			fmt.Printf("[*] Summary for param '%s': %d raw, %d escaped\n\n", param, rawHitCount, escapedHitCount)
		}
	}

	return results
}

// printBanner prints the application banner
func printBanner() {
	banner := `
 __   __ _____ _____                 _   
 \ \ / // ____/ ____|              	| |  
  \ V /| (___| (___  _ __   ___  ___| |_ 
   > <  \___ \\___ \| '_ \ / _ \/ __| __|
  / . \ ____) |___) | |_) |  __/ (__| |_ 
 /_/ \_\_____/_____/| .__/ \___|\___|\__|
                    | |                  
                    |_|                  
 Reflected XSS Scanner
 ========================================
`
	fmt.Println(banner)
}
