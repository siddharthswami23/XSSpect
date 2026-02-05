package scanner

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"
	"time"
)

// ScanResult holds the result of a single payload test
type ScanResult struct {
	Parameter       string
	Payload         string
	ReflectionType  ReflectionType
	BrowserVerified bool
	XSSEventType    string
}

// ScanSummary holds the complete scan summary
type ScanSummary struct {
	TargetURL            string
	Method               string
	Parameters           []string
	TotalPayloads        int
	StartTime            time.Time
	EndTime              time.Time
	Results              []ScanResult
	RawCount             int
	EscapedCount         int
	VerifiedCount        int
	BrowserVerifyEnabled bool
}

// SaveReport saves the TXT report to a file
func SaveReport(summary *ScanSummary, outputPath string) error {
	report := GenerateBasicReport(summary)
	err := os.WriteFile(outputPath, []byte(report), 0644)
	if err != nil {
		return fmt.Errorf("failed to save report: %w", err)
	}
	return nil
}

// SaveCSVReport saves the scan results as CSV for visualization tools like Google Looker Studio
func SaveCSVReport(summary *ScanSummary, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write CSV header
	header := []string{
		"Timestamp",
		"Target_URL",
		"HTTP_Method",
		"Parameter",
		"Payload",
		"Reflection_Type",
		"Browser_Verified",
		"XSS_Event_Type",
		"Severity",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write each result as a row
	timestamp := summary.EndTime.Format("2006-01-02 15:04:05")
	for _, result := range summary.Results {
		// Determine severity based on reflection type and browser verification
		severity := getSeverity(result)

		// Get reflection type string
		reflectionType := result.ReflectionType.String()

		// Browser verified string
		browserVerified := "No"
		if result.BrowserVerified {
			browserVerified = "Yes"
		}

		row := []string{
			timestamp,
			summary.TargetURL,
			summary.Method,
			result.Parameter,
			result.Payload,
			reflectionType,
			browserVerified,
			result.XSSEventType,
			severity,
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	return nil
}

// getSeverity determines the severity level based on the result
func getSeverity(result ScanResult) string {
	switch result.ReflectionType {
	case RawReflection:
		if result.BrowserVerified {
			return "Critical"
		}
		return "High"
	case EscapedReflection:
		return "Low"
	default:
		return "Info"
	}
}

// GenerateBasicReport generates a basic TXT report
func GenerateBasicReport(summary *ScanSummary) string {
	var sb strings.Builder

	sb.WriteString("================================================================================\n")
	sb.WriteString("                         XSSpect Security Report\n")
	sb.WriteString("================================================================================\n")

	sb.WriteString("SCAN DETAILS\n")
	sb.WriteString("------------\n")
	sb.WriteString(fmt.Sprintf("Target URL: %s\n", summary.TargetURL))
	sb.WriteString(fmt.Sprintf("HTTP Method: %s\n", summary.Method))
	sb.WriteString(fmt.Sprintf("Parameters Tested: %s\n", strings.Join(summary.Parameters, ", ")))
	sb.WriteString(fmt.Sprintf("Total Payloads: %d\n", summary.TotalPayloads))
	sb.WriteString(fmt.Sprintf("Scan Start: %s\n", summary.StartTime.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("Scan End: %s\n", summary.EndTime.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("Duration: %s\n", summary.EndTime.Sub(summary.StartTime).Round(time.Second)))
	sb.WriteString(fmt.Sprintf("Browser Verification: %v\n\n", summary.BrowserVerifyEnabled))

	sb.WriteString("RESULTS SUMMARY\n")
	sb.WriteString("---------------\n")
	sb.WriteString(fmt.Sprintf("RAW XSS Found: %d\n", summary.RawCount))
	sb.WriteString(fmt.Sprintf("Browser Verified: %d\n", summary.VerifiedCount))
	sb.WriteString(fmt.Sprintf("Escaped Reflections: %d\n\n", summary.EscapedCount))

	// Risk Assessment
	sb.WriteString("RISK ASSESSMENT\n")
	sb.WriteString("---------------\n")
	if summary.VerifiedCount > 0 {
		sb.WriteString("Severity: CRITICAL\n")
		sb.WriteString("The application is vulnerable to XSS attacks. Browser verification confirmed that\n")
		sb.WriteString("malicious scripts can be executed in the user's browser.\n\n")
	} else if summary.RawCount > 0 {
		sb.WriteString("Severity: HIGH\n")
		sb.WriteString("The application reflects user input without proper sanitization.\n")
		sb.WriteString("This may lead to XSS vulnerabilities.\n\n")
	} else if summary.EscapedCount > 0 {
		sb.WriteString("Severity: LOW\n")
		sb.WriteString("The application properly escapes user input in most cases.\n\n")
	} else {
		sb.WriteString("Severity: INFO\n")
		sb.WriteString("No reflections detected. The application may be secure against reflected XSS.\n\n")
	}

	if summary.RawCount > 0 {
		sb.WriteString("VULNERABILITIES FOUND\n")
		sb.WriteString("---------------------\n")
		vulnNum := 1
		for _, result := range summary.Results {
			if result.ReflectionType == RawReflection {
				sb.WriteString(fmt.Sprintf("\n[%d] Parameter: %s\n", vulnNum, result.Parameter))
				sb.WriteString(fmt.Sprintf("    Payload: %s\n", result.Payload))
				if result.BrowserVerified {
					sb.WriteString(fmt.Sprintf("    Status: VERIFIED (%s() executed in browser)\n", result.XSSEventType))
					sb.WriteString("    Severity: CRITICAL\n")
				} else {
					sb.WriteString("    Status: RAW REFLECTION (Static Analysis)\n")
					sb.WriteString("    Severity: HIGH\n")
				}
				vulnNum++
			}
		}
	} else {
		sb.WriteString("No XSS vulnerabilities found.\n")
	}

	sb.WriteString("\n\nREMEDIATION RECOMMENDATIONS\n")
	sb.WriteString("---------------------------\n")
	sb.WriteString("1. Implement proper output encoding based on context (HTML, JavaScript, URL, CSS)\n")
	sb.WriteString("2. Use Content Security Policy (CSP) headers\n")
	sb.WriteString("3. Validate and sanitize all user inputs on the server-side\n")
	sb.WriteString("4. Use HTTPOnly and Secure flags for cookies\n")
	sb.WriteString("5. Consider using a Web Application Firewall (WAF)\n")

	sb.WriteString("\n\n================================================================================\n")
	sb.WriteString("                              End of Report\n")
	sb.WriteString("================================================================================\n")
	sb.WriteString("\nGenerated by XSScan\n")

	return sb.String()
}
