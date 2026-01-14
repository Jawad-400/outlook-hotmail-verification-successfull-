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
	"sync/atomic"
	"time"
)

// User-Agent rotation system
var userAgentIndex uint32 = 0

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/122.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
}

func getNextUserAgent() string {
	index := atomic.AddUint32(&userAgentIndex, 1) % uint32(len(userAgents))
	return userAgents[index]
}

func CheckEmailAvailability(email string) (bool, []string, error) {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Timeout: 30 * time.Second,
		Jar:     jar,
	}

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
		return false, nil, err
	}

	currentUserAgent := getNextUserAgent()
	req1.Header.Set("User-Agent", currentUserAgent)
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
		return false, nil, err
	}
	defer resp1.Body.Close()

	var bodyReader io.Reader = resp1.Body
	if resp1.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(resp1.Body)
		if err != nil {
			return false, nil, err
		}
		defer gzReader.Close()
		bodyReader = gzReader
	}

	body1, err := io.ReadAll(bodyReader)
	if err != nil {
		return false, nil, err
	}

	pageContent := string(body1)

	canaryToken := ""
	patterns := []string{
		`"apiCanary":"([^"]+)"`,
		`apiCanary['"]?\s*:\s*['"]([^'"]+)['"]`,
		`canary['"]?\s*:\s*['"]([^'"]+)['"]`,
		`"canary":"([^"]+)"`,
	}

	for _, pattern := range patterns {
		if token := extractValue(pageContent, pattern); token != "" {
			canaryToken = token
			break
		}
	}

	if strings.Contains(canaryToken, `\u`) {
		canaryToken = decodeUnicodeEscapes(canaryToken)
	}

	if canaryToken == "" {
		for _, cookie := range resp1.Cookies() {
			if cookie.Name == "amcanary" || cookie.Name == "canary" {
				canaryToken = cookie.Value
				break
			}
		}
	}

	if canaryToken == "" {
		return false, nil, fmt.Errorf("cannot extract canary token")
	}

	correlationID := ""
	corrPatterns := []string{
		`"correlationId":"([^"]+)"`,
		`correlationId['"]?\s*:\s*['"]([^'"]+)['"]`,
		`sUnauthSessionID['"]?\s*:\s*['"]([^'"]+)['"]`,
		`"uaid":"([^"]+)"`,
	}

	for _, pattern := range corrPatterns {
		if id := extractValue(pageContent, pattern); id != "" {
			correlationID = id
			break
		}
	}

	if correlationID == "" || correlationID == "677faeb59376291a72029b0008873e31" {
		correlationID = generateRandomID()
	}

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
		return false, nil, err
	}

	req2, err := http.NewRequest("POST", apiURL, strings.NewReader(string(requestBodyBytes)))
	if err != nil {
		return false, nil, err
	}

	req2.Header.Set("Content-Type", "application/json; charset=utf-8")
	req2.Header.Set("Accept", "application/json")
	req2.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req2.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	req2.Header.Set("Origin", "https://signup.live.com")
	req2.Header.Set("Referer", signupURL)
	req2.Header.Set("User-Agent", currentUserAgent)
	req2.Header.Set("canary", canaryToken)
	req2.Header.Set("client-request-id", correlationID)
	req2.Header.Set("correlationId", correlationID)
	req2.Header.Set("hpgact", "0")
	req2.Header.Set("hpgid", "200225")

	for _, cookie := range resp1.Cookies() {
		req2.AddCookie(cookie)
	}

	resp2, err := client.Do(req2)
	if err != nil {
		return false, nil, err
	}
	defer resp2.Body.Close()

	var apiBodyReader io.Reader = resp2.Body
	if resp2.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(resp2.Body)
		if err != nil {
			return false, nil, err
		}
		defer gzReader.Close()
		apiBodyReader = gzReader
	}

	body2, err := io.ReadAll(apiBodyReader)
	if err != nil {
		return false, nil, err
	}

	response := string(body2)

	if strings.Contains(response, `"isAvailable":true`) {
		return true, nil, nil
	}

	if strings.Contains(response, `"isAvailable":false`) {
		suggestions := extractSuggestions(response)
		return false, suggestions, nil
	}

	return false, nil, fmt.Errorf("unexpected response")
}

func extractValue(content, pattern string) string {
	re := regexp.MustCompile(pattern)
	if matches := re.FindStringSubmatch(content); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func decodeUnicodeEscapes(s string) string {
	var result strings.Builder
	for i := 0; i < len(s); i++ {
		if i+5 < len(s) && s[i] == '\\' && s[i+1] == 'u' {
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

func main() {
	fmt.Println("Microsoft Outlook Email Checker")
	fmt.Println("================================")

	// Start HTTP server only - no CLI tests
	fmt.Println("API Server running on: http://localhost:8088")
	fmt.Println("Usage: http://localhost:8088/check?email=test@outlook.com")

	http.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Query().Get("email")
		if email == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(400)
			w.Write([]byte(`{"status": "error", "message": "Email parameter is required"}`))
			return
		}

		available, _, err := CheckEmailAvailability(email)

		var response string
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(500)
			response = fmt.Sprintf(`{"status": "error", "message": "%s"}`, err.Error())
		} else if !available { // Email exists (isAvailable: false means exists)
			response = `{"status": "exists"}`
		} else { // Email doesn't exist (isAvailable: true means doesn't exist)
			response = `{"status": "not exists"}`
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(response))
	})

	log.Fatal(http.ListenAndServe(":8088", nil))
}
