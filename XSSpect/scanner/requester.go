package scanner

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	// MaxRetries is the maximum number of retry attempts for network failures
	MaxRetries = 2
	// RequestTimeout is the timeout duration for HTTP requests
	RequestTimeout = 10 * time.Second
)

// RequestConfig holds configuration for HTTP requests
type RequestConfig struct {
	URL    string
	Method string
}

// RequestResult contains the result of an HTTP request
type RequestResult struct {
	StatusCode   int
	ResponseBody string
	Error        error
}

// SendRequest sends an HTTP request with retry logic
// Retries only on network errors (timeout, connection failures)
// Does NOT retry on valid HTTP responses (200, 403, 500, etc.)
func SendRequest(config RequestConfig) RequestResult {
	var lastErr error
	var result RequestResult

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: RequestTimeout,
	}

	// Try up to MaxRetries + 1 times (initial attempt + retries)
	for attempt := 0; attempt <= MaxRetries; attempt++ {
		// Create request
		req, err := http.NewRequest(config.Method, config.URL, nil)
		if err != nil {
			lastErr = err
			continue
		}

		// Set a basic User-Agent to avoid being blocked by some servers
		req.Header.Set("User-Agent", "XSSpect/1.0")

		// Send request
		resp, err := client.Do(req)
		if err != nil {
			// Network error occurred - check if we should retry
			lastErr = err
			if attempt < MaxRetries && isRetryableError(err) {
				// Wait a bit before retrying
				time.Sleep(time.Duration(attempt+1) * time.Second)
				continue
			}
			// Either max retries reached or non-retryable error
			result.Error = err
			return result
		}

		// We got a valid HTTP response - read it and return (no retry)
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			result.Error = fmt.Errorf("failed to read response body: %w", err)
			return result
		}

		result.StatusCode = resp.StatusCode
		result.ResponseBody = string(bodyBytes)
		result.Error = nil
		return result
	}

	// All retries exhausted
	result.Error = fmt.Errorf("request failed after %d retries: %w", MaxRetries, lastErr)
	return result
}

// isRetryableError determines if an error is retryable
// Retryable errors include timeouts and temporary network errors
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := strings.ToLower(err.Error())

	// Check for common retryable error patterns
	retryablePatterns := []string{
		"timeout",
		"connection refused",
		"connection reset",
		"temporary failure",
		"network is unreachable",
		"no route to host",
		"broken pipe",
		"connection timed out",
		"i/o timeout",
	}

	for _, pattern := range retryablePatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	return false
}

// ValidateMethod validates that the HTTP method is supported
func ValidateMethod(method string) error {
	// Convert to uppercase for comparison
	method = strings.ToUpper(method)

	// List of valid HTTP methods
	validMethods := []string{
		"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE",
	}

	for _, valid := range validMethods {
		if method == valid {
			return nil
		}
	}

	return fmt.Errorf("invalid HTTP method: %s", method)
}
