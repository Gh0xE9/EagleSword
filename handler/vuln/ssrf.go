package vuln

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Gh0xE9/EagleSword/config"
	"github.com/Gh0xE9/EagleSword/handler/parse"
	"github.com/Gh0xE9/EagleSword/payload"
)

// SSRFResult SSRF扫描结果
type SSRFResult struct {
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
}

// SSRFScanner SSRF扫描器
type SSRFScanner struct {
	client      *http.Client
	headers     map[string]string
	method      string
	concurrency int
	timeout     time.Duration
	results     []SSRFResult
	mutex       sync.Mutex
	progress    chan int
	total       int
	completed   int
}

// NewSSRFScanner 创建新的SSRF扫描器
func NewSSRFScanner(headers map[string]string, method string, concurrency int, timeout time.Duration) *SSRFScanner {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	return &SSRFScanner{
		client:      client,
		headers:     headers,
		method:      method,
		concurrency: concurrency,
		timeout:     timeout,
		results:     make([]SSRFResult, 0),
		progress:    make(chan int, 100),
	}
}

// ScanTarget 扫描单个目标
func (s *SSRFScanner) ScanTarget(targetURL string, payloads []payload.Payload) []SSRFResult {
	s.total = len(payloads)
	s.completed = 0
	s.results = make([]SSRFResult, 0)

	// 创建并发控制
	semaphore := make(chan struct{}, s.concurrency)
	var wg sync.WaitGroup

	// 启动进度监控
	go s.monitorProgress()

	// 并发扫描
	for _, p := range payloads {
		wg.Add(1)
		go func(payload payload.Payload) {
			defer wg.Done()
			semaphore <- struct{}{}        // 获取信号量
			defer func() { <-semaphore }() // 释放信号量

			result := s.testPayload(targetURL, payload)
			s.addResult(result)
		}(p)
	}

	wg.Wait()
	close(s.progress)

	return s.results
}

// ScanTargetWithParameters 扫描带有参数的目标
func (s *SSRFScanner) ScanTargetWithParameters(reqInfo *parse.RequestInfo, payloads []payload.Payload) []SSRFResult {
	// 解析参数
	parser := parse.NewParameterParser()
	parameters := parser.ParseRequest(reqInfo)

	// 过滤出可能受SSRF影响的参数
	susceptibleParams := parser.FilterSSRFSusceptibleParameters(parameters)

	if len(susceptibleParams) == 0 {
		fmt.Println(config.ColorYellow("[SSRF] 未发现可能受SSRF影响的参数"))
		return []SSRFResult{}
	}

	fmt.Printf(config.ColorCyan("[SSRF] 发现 %d 个可能受SSRF影响的参数\n"), len(susceptibleParams))

	// 为每个参数生成测试payload
	var allResults []SSRFResult

	for _, param := range susceptibleParams {
		fmt.Printf(config.ColorBlue("[SSRF] 测试参数: %s (%s)\n"), param.Name, param.Location)

		// 为这个参数测试所有payload
		paramResults := s.testParameterWithPayloads(reqInfo, param, payloads)
		allResults = append(allResults, paramResults...)
	}

	return allResults
}

// testParameterWithPayloads 测试参数的所有payload
func (s *SSRFScanner) testParameterWithPayloads(reqInfo *parse.RequestInfo, param parse.ParameterInfo, payloads []payload.Payload) []SSRFResult {
	var results []SSRFResult

	// 创建并发控制
	semaphore := make(chan struct{}, s.concurrency)
	var wg sync.WaitGroup

	for _, p := range payloads {
		wg.Add(1)
		go func(payload payload.Payload) {
			defer wg.Done()
			semaphore <- struct{}{}        // 获取信号量
			defer func() { <-semaphore }() // 释放信号量

			result := s.testParameterPayload(reqInfo, param, payload)
			results = append(results, result)
		}(p)
	}

	wg.Wait()
	return results
}

// testParameterPayload 测试单个参数的单个payload
func (s *SSRFScanner) testParameterPayload(reqInfo *parse.RequestInfo, param parse.ParameterInfo, payload payload.Payload) SSRFResult {
	result := SSRFResult{
		URL:         reqInfo.URL,
		Payload:     payload.Value,
		Type:        payload.Type,
		Description: payload.Description,
		Severity:    payload.Severity,
		Keywords:    payload.Keywords,
		Parameter:   param.Name,
		Location:    param.Location,
		Time:        time.Now(),
	}

	// 构建请求
	req, err := s.buildParameterRequest(reqInfo, param, payload.Value)
	if err != nil {
		result.Error = fmt.Sprintf("构建请求失败: %v", err)
		return result
	}

	// 发送请求
	resp, err := s.client.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("请求失败: %v", err)
		return result
	}
	defer resp.Body.Close()

	result.Status = resp.StatusCode

	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = fmt.Sprintf("读取响应失败: %v", err)
		return result
	}

	result.Response = string(body)

	// 分析响应
	result.Matched = s.analyzeResponse(result.Response, payload.Keywords)

	return result
}

// buildParameterRequest 构建带参数的HTTP请求
func (s *SSRFScanner) buildParameterRequest(reqInfo *parse.RequestInfo, param parse.ParameterInfo, payload string) (*http.Request, error) {
	var req *http.Request
	var err error

	switch param.Location {
	case "url":
		// 修改URL参数
		req, err = s.buildURLParameterRequest(reqInfo, param.Name, payload)
	case "post":
		// 修改POST参数
		req, err = s.buildPostParameterRequest(reqInfo, param.Name, payload)
	case "json":
		// 修改JSON参数
		req, err = s.buildJSONParameterRequest(reqInfo, param.Name, payload)
	default:
		return nil, fmt.Errorf("不支持的参数位置: %s", param.Location)
	}

	if err != nil {
		return nil, err
	}

	// 设置默认User-Agent
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	// 设置自定义headers
	for key, value := range s.headers {
		req.Header.Set(key, value)
	}

	return req, nil
}

// buildURLParameterRequest 构建URL参数请求
func (s *SSRFScanner) buildURLParameterRequest(reqInfo *parse.RequestInfo, paramName, payload string) (*http.Request, error) {
	parsedURL, err := url.Parse(reqInfo.URL)
	if err != nil {
		return nil, err
	}

	// 修改指定参数
	query := parsedURL.Query()
	query.Set(paramName, payload)
	parsedURL.RawQuery = query.Encode()

	// 创建请求
	req, err := http.NewRequest(reqInfo.Method, parsedURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// buildPostParameterRequest 构建POST参数请求
func (s *SSRFScanner) buildPostParameterRequest(reqInfo *parse.RequestInfo, paramName, payload string) (*http.Request, error) {
	// 解析原始POST数据
	values, err := url.ParseQuery(reqInfo.PostData)
	if err != nil {
		return nil, err
	}

	// 修改指定参数
	values.Set(paramName, payload)

	// 创建请求
	req, err := http.NewRequest(reqInfo.Method, reqInfo.URL, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}

	// 设置Content-Type
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req, nil
}

// buildJSONParameterRequest 构建JSON参数请求
func (s *SSRFScanner) buildJSONParameterRequest(reqInfo *parse.RequestInfo, paramName, payload string) (*http.Request, error) {
	// 解析JSON数据
	var jsonObj map[string]interface{}
	if err := json.Unmarshal([]byte(reqInfo.JSONData), &jsonObj); err != nil {
		return nil, err
	}

	// 修改指定参数
	s.setJSONParameter(jsonObj, paramName, payload)

	// 重新编码JSON
	jsonData, err := json.Marshal(jsonObj)
	if err != nil {
		return nil, err
	}

	// 创建请求
	req, err := http.NewRequest(reqInfo.Method, reqInfo.URL, strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, err
	}

	// 设置Content-Type
	req.Header.Set("Content-Type", "application/json")

	return req, nil
}

// setJSONParameter 设置JSON参数值
func (s *SSRFScanner) setJSONParameter(obj map[string]interface{}, paramName, value string) {
	// 处理嵌套参数 (如 "user.profile.avatar")
	parts := strings.Split(paramName, ".")
	current := obj

	for i, part := range parts {
		if i == len(parts)-1 {
			// 最后一个部分，设置值
			current[part] = value
		} else {
			// 中间部分，确保存在
			if _, exists := current[part]; !exists {
				current[part] = make(map[string]interface{})
			}
			if next, ok := current[part].(map[string]interface{}); ok {
				current = next
			} else {
				// 如果类型不匹配，创建新的map
				current[part] = make(map[string]interface{})
				current = current[part].(map[string]interface{})
			}
		}
	}
}

// testPayload 测试单个payload
func (s *SSRFScanner) testPayload(targetURL string, payload payload.Payload) SSRFResult {
	result := SSRFResult{
		URL:         targetURL,
		Payload:     payload.Value,
		Type:        payload.Type,
		Description: payload.Description,
		Severity:    payload.Severity,
		Keywords:    payload.Keywords,
		Time:        time.Now(),
	}

	// 构建请求
	req, err := s.buildRequest(targetURL, payload.Value)
	if err != nil {
		result.Error = fmt.Sprintf("构建请求失败: %v", err)
		return result
	}

	// 发送请求
	resp, err := s.client.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("请求失败: %v", err)
		return result
	}
	defer resp.Body.Close()

	result.Status = resp.StatusCode

	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = fmt.Sprintf("读取响应失败: %v", err)
		return result
	}

	result.Response = string(body)

	// 分析响应
	result.Matched = s.analyzeResponse(result.Response, payload.Keywords)

	return result
}

// buildRequest 构建HTTP请求
func (s *SSRFScanner) buildRequest(targetURL, payload string) (*http.Request, error) {
	// 解析目标URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	// 构建请求URL，将payload作为参数
	query := parsedURL.Query()
	query.Set("url", payload)
	parsedURL.RawQuery = query.Encode()

	// 创建请求
	req, err := http.NewRequest(s.method, parsedURL.String(), nil)
	if err != nil {
		return nil, err
	}

	// 设置默认User-Agent
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	// 设置自定义headers
	for key, value := range s.headers {
		req.Header.Set(key, value)
	}

	return req, nil
}

// analyzeResponse 分析响应内容
func (s *SSRFScanner) analyzeResponse(response string, keywords []string) bool {
	if len(keywords) == 0 {
		return false
	}

	responseLower := strings.ToLower(response)
	for _, keyword := range keywords {
		if strings.Contains(responseLower, strings.ToLower(keyword)) {
			return true
		}
	}

	return false
}

// addResult 添加扫描结果
func (s *SSRFScanner) addResult(result SSRFResult) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.results = append(s.results, result)
	s.completed++
	s.progress <- s.completed
}

// monitorProgress 监控扫描进度
func (s *SSRFScanner) monitorProgress() {
	for completed := range s.progress {
		percentage := float64(completed) / float64(s.total) * 100
		fmt.Printf("\r[SSRF] 扫描进度: %d/%d (%.1f%%)", completed, s.total, percentage)
	}
	fmt.Println()
}

// SetResults 设置扫描结果
func (s *SSRFScanner) SetResults(results []SSRFResult) {
	s.results = results
}

// PrintResults 打印扫描结果
func (s *SSRFScanner) PrintResults() {
	if len(s.results) == 0 {
		fmt.Println(config.ColorYellow("[SSRF] 未发现SSRF漏洞"))
		return
	}

	// 按严重程度排序
	sort.Slice(s.results, func(i, j int) bool {
		severityOrder := map[string]int{"high": 3, "medium": 2, "low": 1}
		return severityOrder[s.results[i].Severity] > severityOrder[s.results[j].Severity]
	})

	fmt.Printf(config.ColorGreen("\n[SSRF] 发现 %d 个潜在SSRF漏洞:\n"), len(s.results))

	for i, result := range s.results {
		if result.Matched || result.Status != 200 {
			s.printResult(i+1, result)
		}
	}
}

// printResult 打印单个结果
func (s *SSRFScanner) printResult(index int, result SSRFResult) {
	// 设置颜色
	var severityColor string
	switch result.Severity {
	case "high":
		severityColor = config.ColorRed("[" + strings.ToUpper(result.Severity) + "]")
	case "medium":
		severityColor = config.ColorYellow("[" + strings.ToUpper(result.Severity) + "]")
	case "low":
		severityColor = config.ColorBlue("[" + strings.ToUpper(result.Severity) + "]")
	default:
		severityColor = "[" + strings.ToUpper(result.Severity) + "]"
	}

	fmt.Printf("%d. %s %s\n", index, severityColor, config.ColorCyan(result.Type))

	fmt.Printf("   Payload: %s\n", result.Payload)
	fmt.Printf("   描述: %s\n", result.Description)
	fmt.Printf("   状态码: %d\n", result.Status)

	if result.Parameter != "" {
		fmt.Printf("   参数: %s (%s)\n", result.Parameter, result.Location)
	}

	if result.Matched {
		fmt.Println(config.ColorGreen("   ✓ 检测到特征关键字"))
	} else if result.Status != 200 {
		fmt.Println(config.ColorYellow("   ⚠ 非200状态码，可能存在SSRF"))
	}

	if result.Error != "" {
		fmt.Printf(config.ColorRed("   错误: %s\n"), result.Error)
	}

	if len(result.Response) > 0 {
		responsePreview := result.Response
		if len(responsePreview) > 200 {
			responsePreview = responsePreview[:200] + "..."
		}
		fmt.Printf("   响应预览: %s\n", responsePreview)
	}

	fmt.Println()
}

// SaveResults 保存结果到文件
func (s *SSRFScanner) SaveResults(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// 写入标题
	fmt.Fprintf(writer, "SSRF扫描结果\n")
	fmt.Fprintf(writer, "扫描时间: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(writer, "目标数量: %d\n", len(s.results))
	fmt.Fprintf(writer, "发现漏洞: %d\n\n", s.countVulnerabilities())

	// 写入结果
	for i, result := range s.results {
		if result.Matched || result.Status != 200 {
			fmt.Fprintf(writer, "%d. [%s] %s\n", i+1, strings.ToUpper(result.Severity), result.Type)
			fmt.Fprintf(writer, "   Payload: %s\n", result.Payload)
			fmt.Fprintf(writer, "   描述: %s\n", result.Description)
			fmt.Fprintf(writer, "   状态码: %d\n", result.Status)
			fmt.Fprintf(writer, "   匹配: %t\n", result.Matched)
			if result.Error != "" {
				fmt.Fprintf(writer, "   错误: %s\n", result.Error)
			}
			fmt.Fprintf(writer, "   响应: %s\n\n", result.Response)
		}
	}

	return nil
}

// countVulnerabilities 统计漏洞数量
func (s *SSRFScanner) countVulnerabilities() int {
	count := 0
	for _, result := range s.results {
		if result.Matched || result.Status != 200 {
			count++
		}
	}
	return count
}

// ParseCIDR 解析CIDR网段
func ParseCIDR(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}

	return ips, nil
}

// incrementIP 递增IP地址
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ParsePortRange 解析端口范围
func ParsePortRange(portRange string) ([]int, error) {
	var ports []int

	if strings.Contains(portRange, "-") {
		parts := strings.Split(portRange, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid port range format")
		}

		start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return nil, err
		}

		end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return nil, err
		}

		for i := start; i <= end; i++ {
			ports = append(ports, i)
		}
	} else {
		port, err := strconv.Atoi(strings.TrimSpace(portRange))
		if err != nil {
			return nil, err
		}
		ports = append(ports, port)
	}

	return ports, nil
}
