package vuln

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Gh0xE9/EagleSword/config"
	"github.com/Gh0xE9/EagleSword/handler/parse"
	"github.com/Gh0xE9/EagleSword/payload"
)

// XSSResult XSS扫描结果
type XSSResult struct {
	URL         string
	Payload     string
	Type        string
	Description string
	Severity    string
	Status      int
	Response    string
	Keywords    []string
	Matched     bool
	Error       string
	Time        time.Time
	Parameter   string // 被测试的参数名
	Location    string // 参数位置: url, post, json
	Context     string // XSS上下文信息
}

// XSSScanner XSS扫描器
type XSSScanner struct {
	client      *http.Client
	headers     map[string]string
	concurrency int
	timeout     time.Duration
	results     []XSSResult
	mutex       sync.Mutex
	progress    chan int
	total       int
}

// NewXSSScanner 创建XSS扫描器
func NewXSSScanner(headers map[string]string, concurrency int, timeout time.Duration) *XSSScanner {
	return &XSSScanner{
		client: &http.Client{
			Timeout: timeout,
		},
		headers:     headers,
		concurrency: concurrency,
		timeout:     timeout,
		results:     make([]XSSResult, 0),
		progress:    make(chan int, 100),
	}
}

// GetXSSPayloads 获取XSS payload列表
func GetXSSPayloads() []payload.XSSPayload {
	return payload.GetAdvancedXSSPayloads()
}

// ScanTarget 扫描单个目标
func (s *XSSScanner) ScanTarget(targetURL string, payloads []payload.XSSPayload) []XSSResult {
	var results []XSSResult

	// 解析URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return []XSSResult{{
			URL:     targetURL,
			Error:   fmt.Sprintf("Failed to parse URL: %v", err),
			Time:    time.Now(),
			Matched: false,
		}}
	}

	// 获取URL参数
	queryParams := parsedURL.Query()
	if len(queryParams) == 0 {
		return []XSSResult{{
			URL:     targetURL,
			Error:   "No parameters found in URL",
			Time:    time.Now(),
			Matched: false,
		}}
	}

	// 测试每个参数
	for paramName := range queryParams {
		for _, payload := range payloads {
			result := s.testXSSPayload(targetURL, paramName, "url", queryParams.Get(paramName), payload)
			if result.Matched {
				results = append(results, result)
			}
		}
	}

	return results
}

// ScanTargetWithParameters 使用参数化请求扫描目标
func (s *XSSScanner) ScanTargetWithParameters(reqInfo *parse.RequestInfo, payloads []payload.XSSPayload) []XSSResult {
	var results []XSSResult

	// 使用参数解析器获取所有参数
	parser := parse.NewParameterParser()
	parameters := parser.ParseRequest(reqInfo)

	// 测试所有参数
	for _, param := range parameters {
		for _, payload := range payloads {
			result := s.testXSSPayload(reqInfo.URL, param.Name, param.Location, param.Value, payload)
			if result.Matched {
				results = append(results, result)
			}
		}
	}

	return results
}

// testXSSPayload 测试单个XSS payload
func (s *XSSScanner) testXSSPayload(targetURL, paramName, location, paramValue string, payload payload.XSSPayload) XSSResult {
	result := XSSResult{
		URL:         targetURL,
		Payload:     payload.Payload,
		Type:        payload.Type,
		Description: payload.Description,
		Severity:    payload.Severity,
		Keywords:    payload.Keywords,
		Context:     payload.Context,
		Parameter:   paramName,
		Location:    location,
		Time:        time.Now(),
		Matched:     false,
	}

	// 构建测试URL
	testURL := s.buildTestURL(targetURL, paramName, payload.Payload)

	// 发送请求
	resp, err := s.client.Get(testURL)
	if err != nil {
		result.Error = fmt.Sprintf("Request failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	result.Status = resp.StatusCode

	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to read response: %v", err)
		return result
	}

	result.Response = string(body)

	// 检测XSS
	result.Matched = s.detectXSS(result.Response, payload)

	return result
}

// buildTestURL 构建测试URL
func (s *XSSScanner) buildTestURL(targetURL, paramName, payload string) string {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}

	query := parsedURL.Query()
	query.Set(paramName, payload)
	parsedURL.RawQuery = query.Encode()

	return parsedURL.String()
}

// detectXSS 检测XSS漏洞
func (s *XSSScanner) detectXSS(response string, payload payload.XSSPayload) bool {
	// 检查payload是否在响应中
	if !strings.Contains(response, payload.Payload) {
		return false
	}

	// 检查关键词
	for _, keyword := range payload.Keywords {
		if !strings.Contains(strings.ToLower(response), strings.ToLower(keyword)) {
			return false
		}
	}

	// 检查脚本标签
	scriptRegex := regexp.MustCompile(`<script[^>]*>.*?</script>`)
	if scriptRegex.MatchString(response) {
		return true
	}

	// 检查事件处理器
	eventRegex := regexp.MustCompile(`on\w+\s*=\s*["']?[^"'>\s]+["']?`)
	if eventRegex.MatchString(response) {
		return true
	}

	// 检查JavaScript协议
	jsProtocolRegex := regexp.MustCompile(`javascript\s*:`)
	if jsProtocolRegex.MatchString(response) {
		return true
	}

	return false
}

// SetResults 设置扫描结果
func (s *XSSScanner) SetResults(results []XSSResult) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.results = results
}

// PrintResults 打印扫描结果
func (s *XSSScanner) PrintResults() {
	if len(s.results) == 0 {
		fmt.Println(config.ColorYellow("[XSS]"), "No XSS vulnerabilities found")
		return
	}

	fmt.Printf(config.ColorRed("[XSS]")+" Found %d XSS vulnerabilities:\n", len(s.results))

	// 按严重程度排序
	sort.Slice(s.results, func(i, j int) bool {
		severityOrder := map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
		return severityOrder[s.results[i].Severity] > severityOrder[s.results[j].Severity]
	})

	for i, result := range s.results {
		severityColor := config.ColorRed
		switch result.Severity {
		case "HIGH":
			severityColor = config.ColorRed
		case "MEDIUM":
			severityColor = config.ColorYellow
		case "LOW":
			severityColor = config.ColorGreen
		}

		fmt.Printf("\n%s [%d] %s XSS Vulnerability\n",
			severityColor(result.Severity), i+1, result.Type)
		fmt.Printf("  %s URL: %s\n", config.ColorCyan("Target:"), result.URL)
		fmt.Printf("  %s Parameter: %s (%s)\n", config.ColorCyan("Parameter:"), result.Parameter, result.Location)
		fmt.Printf("  %s Payload: %s\n", config.ColorCyan("Payload:"), result.Payload)
		fmt.Printf("  %s Description: %s\n", config.ColorCyan("Description:"), result.Description)
		fmt.Printf("  %s Context: %s\n", config.ColorCyan("Context:"), result.Context)
		fmt.Printf("  %s Status: %d\n", config.ColorCyan("Status:"), result.Status)
		fmt.Printf("  %s Time: %s\n", config.ColorCyan("Time:"), result.Time.Format("2006-01-02 15:04:05"))

		if result.Error != "" {
			fmt.Printf("  %s Error: %s\n", config.ColorRed("Error:"), result.Error)
		}
	}
}

// SaveResults 保存扫描结果到文件
func (s *XSSScanner) SaveResults(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// 写入标题
	writer.WriteString("XSS Vulnerability Scan Results\n")
	writer.WriteString("================================\n\n")

	// 写入结果
	for i, result := range s.results {
		writer.WriteString(fmt.Sprintf("[%d] %s XSS Vulnerability\n", i+1, result.Type))
		writer.WriteString(fmt.Sprintf("URL: %s\n", result.URL))
		writer.WriteString(fmt.Sprintf("Parameter: %s (%s)\n", result.Parameter, result.Location))
		writer.WriteString(fmt.Sprintf("Payload: %s\n", result.Payload))
		writer.WriteString(fmt.Sprintf("Description: %s\n", result.Description))
		writer.WriteString(fmt.Sprintf("Severity: %s\n", result.Severity))
		writer.WriteString(fmt.Sprintf("Context: %s\n", result.Context))
		writer.WriteString(fmt.Sprintf("Status: %d\n", result.Status))
		writer.WriteString(fmt.Sprintf("Time: %s\n", result.Time.Format("2006-01-02 15:04:05")))

		if result.Error != "" {
			writer.WriteString(fmt.Sprintf("Error: %s\n", result.Error))
		}

		writer.WriteString("\n" + strings.Repeat("-", 50) + "\n\n")
	}

	return nil
}
