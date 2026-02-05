package scanner

import (
	"strings"
)

// ReflectionType represents the type of reflection detected
type ReflectionType int

const (
	NoReflection ReflectionType = iota
	EscapedReflection
	RawReflection
)

// String returns the string representation of ReflectionType
func (r ReflectionType) String() string {
	switch r {
	case RawReflection:
		return "RAW_REFLECTION"
	case EscapedReflection:
		return "ESCAPED"
	case NoReflection:
		return "NO_REFLECTION"
	default:
		return "UNKNOWN"
	}
}

// AnalysisResult contains the result of analyzing a response
type AnalysisResult struct {
	Type            ReflectionType
	Parameter       string
	Payload         string
	ResponseSnippet string
}

// AnalyzeResponse analyzes the HTTP response body to detect XSS reflection
// Returns the type of reflection detected according to these rules:
// 1. RAW_REFLECTION: Exact payload string found in response body
// 2. ESCAPED: Payload present but HTML-escaped (< > " ')
// 3. NO_REFLECTION: Payload not found
func AnalyzeResponse(responseBody, payload, parameter string) AnalysisResult {
	result := AnalysisResult{
		Parameter: parameter,
		Payload:   payload,
	}

	// Extract a small snippet from the response (30-40 characters around the payload)
	snippetLength := 40
	if len(responseBody) > snippetLength {
		result.ResponseSnippet = responseBody[:snippetLength]
	} else {
		result.ResponseSnippet = responseBody
	}

	// Check for exact payload (RAW_REFLECTION)
	// Only consider it a reflection if the COMPLETE payload is found
	// This prevents false positives from partial matches like "<script" existing naturally in HTML
	if strings.Contains(responseBody, payload) {
		// Additional verification: check if this is a real reflection
		// by ensuring the payload is substantial enough (not just a single character or very short string)
		// or verify it's not just part of the normal HTML structure
		if len(payload) >= 3 || !isCommonHTMLFragment(payload) {
			// Check if payload is in a dangerous/executable context
			if isInDangerousContext(responseBody, payload) {
				result.Type = RawReflection
				return result
			}
			// If payload exists but in safe context, treat as escaped
			result.Type = EscapedReflection
			return result
		}
	}

	// Check for escaped payload (ESCAPED)
	// HTML entities that might be escaped: < > " ' &
	escapedPayload := escapeHTML(payload)
	if escapedPayload != payload && strings.Contains(responseBody, escapedPayload) {
		result.Type = EscapedReflection
		return result
	}

	// Check for partial escaping - sometimes only some characters are escaped
	// Try multiple escape patterns
	escapePatterns := []struct {
		from string
		to   string
	}{
		{"<", "&lt;"},
		{">", "&gt;"},
		{"\"", "&quot;"},
		{"'", "&#39;"},
		{"'", "&apos;"},
		{"&", "&amp;"},
	}

	// Build different escaped versions
	testPayload := payload
	for _, pattern := range escapePatterns {
		testPayload = strings.ReplaceAll(testPayload, pattern.from, pattern.to)
		if strings.Contains(responseBody, testPayload) {
			result.Type = EscapedReflection
			return result
		}
	}

	// Also check for HTML entity numeric encoding
	if containsEncodedPayload(responseBody, payload) {
		result.Type = EscapedReflection
		return result
	}

	// No reflection found
	result.Type = NoReflection
	return result
}

// escapeHTML escapes special HTML characters
func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}

// containsEncodedPayload checks if the response contains HTML entity encoded version of payload
func containsEncodedPayload(responseBody, payload string) bool {
	// Check for numeric HTML entities (decimal and hex)
	for _, char := range payload {
		// Decimal encoding: &#60; for <
		decEncoded := "&#" + string(rune(char)) + ";"
		if strings.Contains(responseBody, decEncoded) {
			return true
		}
	}
	return false
}

// isCommonHTMLFragment checks if a string is a common HTML fragment that naturally appears in pages
func isCommonHTMLFragment(s string) bool {
	commonFragments := []string{
		"<script", "</script>", "<script>",
		"<style", "</style>", "<style>",
		"<div", "</div>", "<div>",
		"<span", "</span>", "<span>",
		"<svg", "</svg>", "<svg>",
		"<img", "</img>", "<img>",
		"<a", "</a>", "<a>",
		"<body", "</body>", "<body>",
		"<html", "</html>", "<html>",
		"<head", "</head>", "<head>",
		"<link", "</link>", "<link>",
		"<meta", "</meta>", "<meta>",
		"<iframe", "</iframe>", "<iframe>",
		"<form", "</form>", "<form>",
		"<input", "</input>", "<input>",
		"<button", "</button>", "<button>",
		"<p", "</p>", "<p>",
		"<h1", "</h1>", "<h1>",
		"<h2", "</h2>", "<h2>",
		"<h3", "</h3>", "<h3>",
		"<ul", "</ul>", "<ul>",
		"<li", "</li>", "<li>",
		"<table", "</table>", "<table>",
		"<tr", "</tr>", "<tr>",
		"<td", "</td>", "<td>",
	}

	for _, fragment := range commonFragments {
		if s == fragment {
			return true
		}
	}
	return false
}

// isInDangerousContext checks if the payload appears in an executable context
// Returns true if payload is likely to execute, false if in safe context
func isInDangerousContext(responseBody, payload string) bool {
	// Find the position of the payload in the response
	index := strings.Index(responseBody, payload)
	if index == -1 {
		return false
	}

	// Extract context around the payload (500 chars before and after)
	contextStart := index - 500
	if contextStart < 0 {
		contextStart = 0
	}
	contextEnd := index + len(payload) + 500
	if contextEnd > len(responseBody) {
		contextEnd = len(responseBody)
	}
	context := responseBody[contextStart:contextEnd]
	contextLower := strings.ToLower(context)

	// Check if payload is in SAFE (non-executable) contexts
	safeContexts := []string{
		"<!--",        // HTML comment
		"<title>",     // Title tag (displays but doesn't execute)
		"<textarea",   // Textarea (displays as text)
		"<noscript>",  // NoScript tag
		"<style",      // Style tag (CSS, not JS)
		"<xmp>",       // XMP tag (deprecated, displays as text)
		"<plaintext>", // Plaintext tag (displays as text)
		"<listing>",   // Listing tag (displays as text)
	}

	// Check if payload is within any safe context
	payloadPos := strings.Index(contextLower, strings.ToLower(payload))
	for _, safeCtx := range safeContexts {
		safeStart := strings.LastIndex(contextLower[:payloadPos], safeCtx)
		if safeStart != -1 {
			// Check if there's a closing tag after payload
			closingTags := map[string]string{
				"<!--":        "-->",
				"<title>":     "</title>",
				"<textarea":   "</textarea>",
				"<noscript>":  "</noscript>",
				"<style":      "</style>",
				"<xmp>":       "</xmp>",
				"<plaintext>": "",
				"<listing>":   "</listing>",
			}

			closingTag := closingTags[safeCtx]
			if closingTag == "" {
				// Tags like <plaintext> don't have closing tags
				return false
			}

			closingPos := strings.Index(contextLower[payloadPos:], closingTag)
			if closingPos == -1 || closingPos > len(payload) {
				// Payload is between opening and closing safe tags
				return false
			}
		}
	}

	// If we reach here, payload is likely in a dangerous/executable context
	return true
}
