# XSSpect Workflow

## High-Level Process Flow

```
Start
  ↓
Input Validation
  ↓
Load Payloads
  ↓
Initialize Scan
  ↓
Inject Payload
  ↓
Send Request
  ↓
Analyze Response
  ↓
Browser Verify (Optional)
  ↓
Store Result
  ↓
Generate Report
  ↓
End
```

---

## Function Calls for Each Step

### 1. Start
```go
main()
parseArgs()
flag.Parse()
printBanner()
```

### 2. Input Validation
```go
scanner.ValidateURL(config.URL)
scanner.ValidateMethod(config.Method)
// Validate parameters list not empty
```

### 3. Load Payloads
```go
// Option A: Single custom payload
payloads = []string{config.CustomPayload}

// Option B: Load from file
loadPayloadsFromFile(config.PayloadFile)
  └─> os.Open()
  └─> bufio.NewScanner()

// Option C: Load built-in payloads
loadPayloads()
  └─> os.Open("payloads/payloads.txt")
  └─> bufio.NewScanner()
```

### 4. Initialize Scan
```go
// Create scan summary
scanSummary := &scanner.ScanSummary{...}

// Initialize browser (if --browser-verify enabled)
scanner.NewBrowserVerifier(browserConfig)
browserVerifier.Start()
  └─> selenium.NewChromeDriverService()
  └─> selenium.NewRemote()
```

### 5. Inject Payload
```go
scanner.BuildRequestURL(config.URL, param, payload)
  └─> scanner.InjectPayload(baseURL, parameter, payload)
      └─> url.Parse(baseURL)
      └─> queryParams.Set(parameter, payload)
      └─> parsedURL.RawQuery = queryParams.Encode()
```

### 6. Send Request
```go
scanner.SendRequest(reqConfig)
  └─> http.NewRequest(method, url, nil)
  └─> req.Header.Set("User-Agent", "XSSpect/1.0")
  └─> client.Do(req)
  └─> io.ReadAll(resp.Body)
```

### 7. Analyze Response
```go
scanner.AnalyzeResponse(result.ResponseBody, payload, param)
  └─> strings.Contains(responseBody, payload)
  └─> isInDangerousContext(responseBody, payload)
  └─> escapeHTML(payload)
  └─> Return AnalysisResult{Type, Parameter, Payload}
```

### 8. Browser Verify (Optional)
```go
browserVerifier.VerifyWithRetry(testURL, retries)
  └─> browserVerifier.VerifyXSSExecution(url)
      └─> driver.SetPageLoadTimeout()
      └─> driver.Get(url)
      └─> driver.AlertText()
      └─> driver.DismissAlert()
      └─> driver.ExecuteScript()
```

### 9. Store Result
```go
scanResult := scanner.ScanResult{
    Parameter:       param,
    Payload:         payload,
    ReflectionType:  analysis.Type,
    BrowserVerified: browserVerified,
    XSSEventType:    xssEventType,
}
results = append(results, scanResult)
scanSummary.Results = append(scanSummary.Results, paramResults...)
```

### 10. Generate Report
```go
scanner.SaveCSVReport(scanSummary, config.CSVOutput)
  └─> os.Create(outputPath)
  └─> csv.NewWriter(file)
  └─> writer.Write(header)
  └─> writer.Write(row) // for each result
  └─> writer.Flush()

exec.Command("rclone", "sync", "./outputs", "gdrive:csv-data")
  └─> cmd.Run()
```

### 11. End
```go
browserVerifier.Close()
  └─> driver.Quit()
  └─> service.Stop()

// Print completion message
// Exit program
```

---

## Complete Function Call Sequence

```
main()
├─> parseArgs()
│   └─> flag.Parse()
├─> printBanner()
├─> scanner.ValidateURL()
├─> scanner.ValidateMethod()
├─> loadPayloads() / loadPayloadsFromFile()
├─> scanner.NewBrowserVerifier()
├─> browserVerifier.Start()
│
└─> FOR EACH param:
    └─> FOR EACH payload:
        ├─> scanner.BuildRequestURL()
        │   └─> scanner.InjectPayload()
        ├─> scanner.SendRequest()
        ├─> scanner.AnalyzeResponse()
        ├─> browserVerifier.VerifyWithRetry()
        │   └─> browserVerifier.VerifyXSSExecution()
        └─> append to results

├─> scanner.SaveCSVReport()
├─> exec.Command("rclone", "sync")
└─> browserVerifier.Close()
```
