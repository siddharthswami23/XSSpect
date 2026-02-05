package scanner

import (
	"net/url"
	"strings"
)

// InjectPayload injects a payload into a specific parameter of the target URL
// Only modifies the specified parameter, leaving other parameters unchanged
// Returns the complete URL with the injected payload
func InjectPayload(baseURL, parameter, payload string) (string, error) {
	// Parse the base URL
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	// Get existing query parameters
	queryParams := parsedURL.Query()

	// Set or update the specified parameter with the payload
	// Raw payload injection - no encoding
	queryParams.Set(parameter, payload)

	// Build the new URL with injected payload
	parsedURL.RawQuery = queryParams.Encode()

	return parsedURL.String(), nil
}

// BuildRequestURL creates the full URL for the HTTP request
// For GET requests, parameters go in the query string
// For POST/PUT/etc, parameters still go in query string (as per spec)
func BuildRequestURL(baseURL, parameter, payload string) (string, error) {
	return InjectPayload(baseURL, parameter, payload)
}

// ExtractBaseURL extracts the base URL without query parameters
func ExtractBaseURL(rawURL string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	// Remove query string and fragment
	parsedURL.RawQuery = ""
	parsedURL.Fragment = ""

	return parsedURL.String(), nil
}

// ValidateURL validates that the URL has proper format and scheme
func ValidateURL(rawURL string) error {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return err
	}

	// Check for valid scheme (http or https)
	scheme := strings.ToLower(parsedURL.Scheme)
	if scheme != "http" && scheme != "https" {
		return &InvalidURLError{URL: rawURL, Reason: "URL must start with http:// or https://"}
	}

	// Check that host is present
	if parsedURL.Host == "" {
		return &InvalidURLError{URL: rawURL, Reason: "URL must contain a host"}
	}

	return nil
}

// InvalidURLError represents an error for invalid URL format
type InvalidURLError struct {
	URL    string
	Reason string
}

func (e *InvalidURLError) Error() string {
	return "Invalid URL '" + e.URL + "': " + e.Reason
}
