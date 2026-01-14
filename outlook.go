package main

import (
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func CheckEmailWithExactURL(email string) (bool, []string, error) {
	fmt.Printf("\n🎯 Checking: %s\n", email)

	// Create cookie jar
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Timeout: 30 * time.Second,
		Jar:     jar,
	}

	// Step 1: Load the signup page to get fresh cookies and tokens
	fmt.Println("📥 Step 1: Loading signup page for fresh tokens...")

	// Build the signup URL
	signupURL := "https://signup.live.com/signup"
	signupURL += "?sru=https%3a%2f%2flogin.live.com%2foauth20_authorize.srf"
	signupURL += "%3flc%3d1033"
	signupURL += "%26client_id%3d9199bf20-a13f-4107-85dc-02114787ef48"
	signupURL += "%26cobrandid%3dab0455a0-8d03-46b9-b18b-df2f57b9e44c"
	signupURL += "%26mkt%3dEN-US"
	signupURL += "%26opid%3dA660A3067066272D"
	signupURL += "%26opidt%3d1768375361"
	signupURL += "%26uaid%3d677faeb59376291a72029b0008873e31"
	signupURL += "%26contextid%3dD9E55480A7490DD6"
	signupURL += "%26opignore%3d1"
	signupURL += "&mkt=EN-US"
	signupURL += "&uiflavor=web"
	signupURL += "&fl=dob%2cflname%2cwld"
	signupURL += "&cobrandid=ab0455a0-8d03-46b9-b18b-df2f57b9e44c"
	signupURL += "&client_id=9199bf20-a13f-4107-85dc-02114787ef48"
	signupURL += "&uaid=677faeb59376291a72029b0008873e31"
	signupURL += "&suc=9199bf20-a13f-4107-85dc-02114787ef48"
	signupURL += "&fluent=2"
	signupURL += "&lic=1"

	req1, err := http.NewRequest("GET", signupURL, nil)
	if err != nil {
		return false, nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Set headers
	req1.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36")
	req1.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req1.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req1.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	req1.Header.Set("Sec-Fetch-Dest", "document")
	req1.Header.Set("Sec-Fetch-Mode", "navigate")
	req1.Header.Set("Sec-Fetch-Site", "none")
	req1.Header.Set("Sec-Fetch-User", "?1")
	req1.Header.Set("Upgrade-Insecure-Requests", "1")

	resp1, err := client.Do(req1)
	if err != nil {
		return false, nil, fmt.Errorf("failed to load page: %v", err)
	}
	defer resp1.Body.Close()

	// Read and decompress if needed
	var bodyReader io.Reader = resp1.Body
	if resp1.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(resp1.Body)
		if err != nil {
			return false, nil, fmt.Errorf("failed to create gzip reader: %v", err)
		}
		defer gzReader.Close()
		bodyReader = gzReader
	}

	body1, err := io.ReadAll(bodyReader)
	if err != nil {
		return false, nil, fmt.Errorf("failed to read response: %v", err)
	}

	pageContent := string(body1)
	fmt.Printf("✅ Page loaded: %d bytes, Status: %d\n", len(body1), resp1.StatusCode)

	// Step 2: Extract canary token from the page
	fmt.Println("🔍 Step 2: Extracting tokens from page...")

	// Extract canary token - try multiple patterns
	canaryToken := ""
	patterns := []string{
		`"apiCanary":"([^"]+)"`,
		`apiCanary['"]?\s*:\s*['"]([^'"]+)['"]`,
		`canary['"]?\s*:\s*['"]([^'"]+)['"]`,
		`"canary":"([^"]+)"`,
		`window\.canary\s*=\s*['"]([^'"]+)['"]`,
		`var canary\s*=\s*['"]([^'"]+)['"]`,
		`FTConfig\.apiCanary\s*=\s*['"]([^'"]+)['"]`,
		`"t":"([^"]+)"`,
	}

	for _, pattern := range patterns {
		if token := extractJSONValue(pageContent, pattern); token != "" {
			canaryToken = token
			fmt.Printf("✅ Found canary with pattern: %s\n", pattern)
			break
		}
	}

	// Decode Unicode escape sequences in canary token
	if strings.Contains(canaryToken, `\u`) {
		canaryToken = decodeUnicodeEscapes(canaryToken)
		fmt.Println("✅ Decoded Unicode escapes in canary token")
	}

	// If not found in page, check cookies
	if canaryToken == "" {
		for _, cookie := range resp1.Cookies() {
			if cookie.Name == "amcanary" || cookie.Name == "canary" {
				canaryToken = cookie.Value
				fmt.Printf("✅ Found canary in cookie: %s\n", cookie.Name)
				break
			}
		}
	}

	if canaryToken == "" {
		// Try to find in script tags
		re := regexp.MustCompile(`<script[^>]*>([\s\S]*?)</script>`)
		scripts := re.FindAllStringSubmatch(pageContent, -1)
		for _, script := range scripts {
			if len(script) > 1 {
				// Look for Config object
				if strings.Contains(script[1], "Config") {
					configRe := regexp.MustCompile(`Config\s*=\s*({[\s\S]*?});`)
					if configMatch := configRe.FindStringSubmatch(script[1]); len(configMatch) > 1 {
						config := configMatch[1]
						if token := extractJSONValue(config, `apiCanary['"]?\s*:\s*['"]([^'"]+)['"]`); token != "" {
							canaryToken = token
							fmt.Println("✅ Found canary in Config object")
							break
						}
					}
				}
			}
		}
	}

	if canaryToken == "" {
		return false, nil, fmt.Errorf("could not extract canary token")
	}

	fmt.Printf("✅ Canary token: %s...\n", canaryToken[:min(50, len(canaryToken))])

	// Extract or generate correlation ID
	correlationID := ""

	// Try to extract from page
	corrPatterns := []string{
		`"correlationId":"([^"]+)"`,
		`correlationId['"]?\s*:\s*['"]([^'"]+)['"]`,
		`sUnauthSessionID['"]?\s*:\s*['"]([^'"]+)['"]`,
		`"sCtx":"([^"]+)"`,
		`"uaid":"([^"]+)"`,
		`uaid['"]?\s*:\s*['"]([^"]+)['"]`,
	}

	for _, pattern := range corrPatterns {
		if id := extractJSONValue(pageContent, pattern); id != "" {
			correlationID = id
			fmt.Printf("✅ Found correlation ID with pattern: %s\n", pattern)
			break
		}
	}

	// If not found, check cookies
	if correlationID == "" {
		for _, cookie := range resp1.Cookies() {
			if cookie.Name == "uaid" || cookie.Name == "MUID" || cookie.Name == "_pxvid" {
				correlationID = cookie.Value
				fmt.Printf("✅ Using cookie as correlation ID: %s\n", cookie.Name)
				break
			}
		}
	}

	// If still not found or using static one, generate fresh one
	if correlationID == "" || correlationID == "677faeb59376291a72029b0008873e31" {
		correlationID = generateRandomID()
		fmt.Printf("✅ Generated fresh correlation ID\n")
	}

	fmt.Printf("✅ Correlation ID: %s\n", correlationID)

	// Step 3: Call the API with extracted tokens
	fmt.Println("📤 Step 3: Calling check API...")

	// Build API URL (same as before)
	apiURL := "https://signup.live.com/API/CheckAvailableSigninNames"
	apiURL += "?sru=https%3a%2f%2flogin.live.com%2foauth20_authorize.srf"
	apiURL += "%3flc%3d1033"
	apiURL += "%26client_id%3d9199bf20-a13f-4107-85dc-02114787ef48"
	apiURL += "%26cobrandid%3dab0455a0-8d03-46b9-b18b-df2f57b9e44c"
	apiURL += "%26mkt%3dEN-US"
	apiURL += "%26opid%3dA660A3067066272D"
	apiURL += "%26opidt%3d1768375361"
	apiURL += "%26uaid%3d677faeb59376291a72029b0008873e31"
	apiURL += "%26contextid%3dD9E55480A7490DD6"
	apiURL += "%26opignore%3d1"
	apiURL += "&mkt=EN-US"
	apiURL += "&uiflavor=web"
	apiURL += "&fl=dob%2cflname%2cwld"
	apiURL += "&cobrandid=ab0455a0-8d03-46b9-b18b-df2f57b9e44c"
	apiURL += "&client_id=9199bf20-a13f-4107-85dc-02114787ef48"
	apiURL += "&uaid=677faeb59376291a72029b0008873e31"
	apiURL += "&suc=9199bf20-a13f-4107-85dc-02114787ef48"
	apiURL += "&fluent=2"
	apiURL += "&lic=1"

	// Create request body (using JSON marshal for proper encoding)
	requestData := map[string]interface{}{
		"includeSuggestions": true,
		"signInName":         email,
		"uiflvr":             1001,
		"scid":               100118,
		"uaid":               correlationID,
		"hpgid":              200225,
	}

	requestBodyBytes, err := json.Marshal(requestData)
	if err != nil {
		return false, nil, fmt.Errorf("failed to marshal request body: %v", err)
	}

	requestBody := string(requestBodyBytes)

	req2, err := http.NewRequest("POST", apiURL, strings.NewReader(requestBody))
	if err != nil {
		return false, nil, fmt.Errorf("failed to create API request: %v", err)
	}

	// Set EXACT headers from curl
	req2.Header.Set("Content-Type", "application/json; charset=utf-8")
	req2.Header.Set("Accept", "application/json")
	req2.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req2.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	req2.Header.Set("Connection", "keep-alive")
	req2.Header.Set("Origin", "https://signup.live.com")
	req2.Header.Set("Referer", signupURL)
	req2.Header.Set("Sec-Fetch-Dest", "empty")
	req2.Header.Set("Sec-Fetch-Mode", "cors")
	req2.Header.Set("Sec-Fetch-Site", "same-origin")
	req2.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36")
	req2.Header.Set("sec-ch-ua", "\"Google Chrome\";v=\"143\", \"Chromium\";v=\"143\", \"Not A(Brand\";v=\"24\"")
	req2.Header.Set("sec-ch-ua-mobile", "?0")
	req2.Header.Set("sec-ch-ua-platform", "\"Windows\"")

	// Critical headers - use the DECODED canary token
	req2.Header.Set("canary", canaryToken)
	req2.Header.Set("client-request-id", correlationID)
	req2.Header.Set("correlationId", correlationID)
	req2.Header.Set("hpgact", "0")
	req2.Header.Set("hpgid", "200225")

	// Copy all cookies from first request
	for _, cookie := range resp1.Cookies() {
		req2.AddCookie(cookie)
	}

	// Also add some common cookies that might be needed
	commonCookies := []*http.Cookie{
		{Name: "mkt", Value: "en-US"},
		{Name: "mkt1", Value: "en-US"},
	}
	for _, cookie := range commonCookies {
		req2.AddCookie(cookie)
	}

	fmt.Printf("📤 Request Body: %s\n", requestBody)

	resp2, err := client.Do(req2)
	if err != nil {
		return false, nil, fmt.Errorf("API request failed: %v", err)
	}
	defer resp2.Body.Close()

	// Read API response
	var apiBodyReader io.Reader = resp2.Body
	if resp2.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(resp2.Body)
		if err != nil {
			return false, nil, fmt.Errorf("failed to create gzip reader for API: %v", err)
		}
		defer gzReader.Close()
		apiBodyReader = gzReader
	}

	body2, err := io.ReadAll(apiBodyReader)
	if err != nil {
		return false, nil, fmt.Errorf("failed to read API response: %v", err)
	}

	response := string(body2)
	fmt.Printf("📥 Response Status: %d\n", resp2.StatusCode)
	fmt.Printf("📥 Response Body: %s\n", response)

	// Parse response
	if strings.Contains(response, `"isAvailable":true`) {
		return true, nil, nil
	}

	if strings.Contains(response, `"isAvailable":false`) {
		suggestions := extractSuggestions(response)
		return false, suggestions, nil
	}

	// Check for error
	if strings.Contains(response, `"error"`) {
		errorCode := extractJSONValue(response, `"code":"([^"]+)"`)
		if errorCode != "" {
			return false, nil, fmt.Errorf("API error %s", errorCode)
		}
		return false, nil, fmt.Errorf("API error: %s", response)
	}

	return false, nil, fmt.Errorf("unexpected response")
}

func decodeUnicodeEscapes(s string) string {
	var result strings.Builder
	for i := 0; i < len(s); i++ {
		if i+5 < len(s) && s[i] == '\\' && s[i+1] == 'u' {
			// Try to parse \uXXXX
			hexStr := s[i+2 : i+6]
			if code, err := strconv.ParseInt(hexStr, 16, 32); err == nil {
				result.WriteRune(rune(code))
				i += 5
			} else {
				result.WriteByte(s[i])
			}
		} else {
			result.WriteByte(s[i])
		}
	}
	return result.String()
}

func extractJSONValue(content, pattern string) string {
	re := regexp.MustCompile(pattern)
	if matches := re.FindStringSubmatch(content); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func extractSuggestions(response string) []string {
	var suggestions []string
	re := regexp.MustCompile(`"suggestions":\[("[^"]+",?)+\]`)
	if match := re.FindString(response); match != "" {
		suggestionRe := regexp.MustCompile(`"([^"]+)"`)
		matches := suggestionRe.FindAllStringSubmatch(match, -1)
		for _, m := range matches {
			if len(m) > 1 {
				suggestions = append(suggestions, m[1])
			}
		}
	}
	return suggestions
}

func generateRandomID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	fmt.Println("\n🚀 Microsoft Email Checker - AUTO TOKEN FETCH")
	fmt.Println(strings.Repeat("=", 60))

	// Test email
	testEmail := "michaeljordan2003@outlook.com"

	fmt.Printf("\n🧪 Testing: %s\n", testEmail)

	start := time.Now()
	available, suggestions, err := CheckEmailWithExactURL(testEmail)
	elapsed := time.Since(start)

	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
	} else if available {
		fmt.Printf("✅ %s is AVAILABLE (took %v)\n", testEmail, elapsed)
	} else {
		fmt.Printf("❌ %s is TAKEN (took %v)\n", testEmail, elapsed)
		if len(suggestions) > 0 {
			fmt.Printf("💡 Suggestions: %v\n", suggestions)
		}
	}

	// Test random email
	randomEmail := fmt.Sprintf("test%d@outlook.com", time.Now().Unix())
	fmt.Printf("\n🧪 Testing random email: %s\n", randomEmail)

	start = time.Now()
	available2, suggestions2, err2 := CheckEmailWithExactURL(randomEmail)
	elapsed = time.Since(start)

	if err2 != nil {
		fmt.Printf("❌ Error: %v\n", err2)
	} else if available2 {
		fmt.Printf("✅ %s is AVAILABLE (took %v)\n", randomEmail, elapsed)
	} else {
		fmt.Printf("❌ %s is TAKEN (took %v)\n", randomEmail, elapsed)
		if len(suggestions2) > 0 {
			fmt.Printf("💡 Suggestions: %v\n", suggestions2)
		}
	}

	// Start HTTP server
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("🌐 API Server: http://localhost:8087/check?email=test@outlook.com")
	fmt.Println(strings.Repeat("=", 60))

	http.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Query().Get("email")
		if email == "" {
			http.Error(w, `{"error": "Email required"}`, 400)
			return
		}

		available, suggestions, err := CheckEmailWithExactURL(email)

		response := fmt.Sprintf(`{
			"email": "%s",
			"available": %v,
			"exists": %v,
			"suggestions": %v,
			"error": %v
		}`, email, available, !available, formatSuggestions(suggestions), formatError(err))

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(response))
	})

	log.Fatal(http.ListenAndServe(":8087", nil))
}

func formatSuggestions(suggestions []string) string {
	if len(suggestions) == 0 {
		return "null"
	}
	return `["` + strings.Join(suggestions, `","`) + `"]`
}

func formatError(err error) string {
	if err == nil {
		return "null"
	}
	return `"` + err.Error() + `"`
}
