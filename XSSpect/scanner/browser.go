package scanner

import (
	"fmt"
	"strings"
	"time"

	"github.com/tebeka/selenium"
	"github.com/tebeka/selenium/chrome"
)

// BrowserConfig holds configuration for browser-based verification
type BrowserConfig struct {
	ChromeDriverPath string
	Headless         bool
	Timeout          time.Duration
}

// BrowserVerifier handles browser-based XSS verification
type BrowserVerifier struct {
	service *selenium.Service
	driver  selenium.WebDriver
	config  BrowserConfig
}

// NewBrowserVerifier creates a new browser verifier
func NewBrowserVerifier(config BrowserConfig) (*BrowserVerifier, error) {
	// Set defaults
	if config.ChromeDriverPath == "" {
		config.ChromeDriverPath = "chromedriver"
	}
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}

	return &BrowserVerifier{
		config: config,
	}, nil
}

// Start initializes the browser
func (bv *BrowserVerifier) Start() error {
	// Start Selenium service with retry and better error handling
	opts := []selenium.ServiceOption{
		selenium.Output(nil), // Suppress ChromeDriver logs
	}

	// Use port 0 to let the OS choose an available port
	const port = 9515 // ChromeDriver default port

	service, err := selenium.NewChromeDriverService(bv.config.ChromeDriverPath, port, opts...)
	if err != nil {
		return fmt.Errorf("failed to start ChromeDriver service: %w\n\nPlease ensure:\n1. Chromium/Chrome browser is installed: sudo apt install chromium-browser\n2. ChromeDriver is installed: sudo apt install chromium-chromedriver\n3. ChromeDriver path is correct: %s", err, bv.config.ChromeDriverPath)
	}
	bv.service = service

	// Configure Chrome capabilities
	caps := selenium.Capabilities{"browserName": "chrome"}
	chromeCaps := chrome.Capabilities{
		Args: []string{
			"--no-sandbox",
			"--disable-dev-shm-usage",
			"--disable-gpu",
			"--disable-extensions",
			"--disable-popup-blocking",
			"--disable-setuid-sandbox",
			"--disable-web-security",
		},
	}

	if bv.config.Headless {
		chromeCaps.Args = append(chromeCaps.Args, "--headless=new")
	}

	caps.AddChrome(chromeCaps)

	// Create WebDriver with timeout
	driver, err := selenium.NewRemote(caps, fmt.Sprintf("http://localhost:%d/wd/hub", port))
	if err != nil {
		bv.service.Stop()
		return fmt.Errorf("failed to create WebDriver: %w\n\nPlease ensure Chromium/Chrome browser is installed", err)
	}
	bv.driver = driver

	return nil
}

// Close stops the browser and service
func (bv *BrowserVerifier) Close() error {
	if bv.driver != nil {
		bv.driver.Quit()
	}
	if bv.service != nil {
		return bv.service.Stop()
	}
	return nil
}

// VerifyXSSExecution verifies if XSS payload actually executes in browser
// Returns true if alert/confirm/prompt was triggered
func (bv *BrowserVerifier) VerifyXSSExecution(url string) (bool, string, error) {
	if bv.driver == nil {
		return false, "", fmt.Errorf("browser not started")
	}

	// Set page load timeout
	err := bv.driver.SetPageLoadTimeout(bv.config.Timeout)
	if err != nil {
		return false, "", fmt.Errorf("failed to set timeout: %w", err)
	}

	// Try to navigate to URL
	// If an alert/confirm/prompt appears, navigation will fail with "unexpected alert open"
	err = bv.driver.Get(url)

	// Check if error is due to alert dialog (this means XSS executed!)
	if err != nil {
		errMsg := err.Error()

		// Detect if alert/confirm/prompt was triggered
		if strings.Contains(errMsg, "unexpected alert open") {
			// XSS detected! An alert dialog appeared
			xssType := "alert" // Default to alert

			if strings.Contains(errMsg, "Alert text") {
				xssType = "alert"
			} else if strings.Contains(errMsg, "confirmation") {
				xssType = "confirm"
			} else if strings.Contains(errMsg, "prompt") {
				xssType = "prompt"
			}

			// Try to dismiss the alert so browser can continue
			bv.driver.DismissAlert()

			return true, xssType, nil
		}

		// Other errors (timeout, network issues, etc.)
		if !strings.Contains(errMsg, "timeout") {
			return false, "", fmt.Errorf("failed to load page: %w", err)
		}
	}

	// If page loaded without error, inject detection script and check
	detectionScript := `
		window.__xss_detected = false;
		window.__xss_type = '';
		
		// Override functions to detect calls
		window.alert = function(msg) {
			window.__xss_detected = true;
			window.__xss_type = 'alert';
			return true;
		};
		
		window.confirm = function(msg) {
			window.__xss_detected = true;
			window.__xss_type = 'confirm';
			return true;
		};
		
		window.prompt = function(msg, defaultText) {
			window.__xss_detected = true;
			window.__xss_type = 'prompt';
			return null;
		};
	`

	// Execute detection script
	_, err = bv.driver.ExecuteScript(detectionScript, nil)
	if err != nil {
		// If script injection fails, try to check for alert anyway
		_, alertErr := bv.driver.AlertText()
		if alertErr == nil {
			// Alert is present!
			bv.driver.DismissAlert()
			return true, "alert", nil
		}
	}

	// Wait a bit for any scripts to execute
	time.Sleep(500 * time.Millisecond)

	// Check if there's an alert present
	_, alertErr := bv.driver.AlertText()
	if alertErr == nil {
		// Alert dialog is present - XSS detected!
		bv.driver.DismissAlert()
		return true, "alert", nil
	}

	// Check if XSS was detected via our injected script
	detected, err := bv.driver.ExecuteScript("return window.__xss_detected || false;", nil)
	if err != nil {
		return false, "", fmt.Errorf("failed to check detection: %w", err)
	}

	xssType, err := bv.driver.ExecuteScript("return window.__xss_type || '';", nil)
	if err != nil {
		xssType = ""
	}

	isDetected := false
	if detectedBool, ok := detected.(bool); ok {
		isDetected = detectedBool
	}

	xssTypeStr := ""
	if xssTypeString, ok := xssType.(string); ok {
		xssTypeStr = xssTypeString
	}

	return isDetected, xssTypeStr, nil
}

// VerifyWithRetry verifies XSS with retry logic
func (bv *BrowserVerifier) VerifyWithRetry(url string, maxRetries int) (bool, string, error) {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		detected, xssType, err := bv.VerifyXSSExecution(url)
		if err == nil {
			return detected, xssType, nil
		}
		lastErr = err

		if attempt < maxRetries {
			time.Sleep(time.Second)
		}
	}

	return false, "", lastErr
}
