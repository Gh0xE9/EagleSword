package parse

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Gh0xE9/EagleSword/config"
)

// JSEndpoint JS文件中发现的接口端点
type JSEndpoint struct {
	URL        string            `json:"url"`
	Method     string            `json:"method"`
	Parameters []string          `json:"parameters"`
	Headers    map[string]string `json:"headers"`
	Source     string            `json:"source"`  // 来源文件或代码片段
	Line       int               `json:"line"`    // 行号
	Context    string            `json:"context"` // 上下文信息
}

// JSAnalyzer JS文件分析器
type JSAnalyzer struct {
	client      *http.Client
	headers     map[string]string
	concurrency int
	timeout     time.Duration
	endpoints   []JSEndpoint
	mutex       sync.Mutex
}

// NewJSAnalyzer 创建JS分析器
func NewJSAnalyzer(headers map[string]string, concurrency int, timeout time.Duration) *JSAnalyzer {
	return &JSAnalyzer{
		client: &http.Client{
			Timeout: timeout,
		},
		headers:     headers,
		concurrency: concurrency,
		timeout:     timeout,
		endpoints:   make([]JSEndpoint, 0),
	}
}

// AnalyzeJSFiles 分析JS文件，提取接口地址
func (a *JSAnalyzer) AnalyzeJSFiles(baseURL string) ([]JSEndpoint, error) {
	// 首先获取目标页面的HTML
	resp, err := a.client.Get(baseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch base URL: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// 解析HTML，提取JS文件链接
	jsFiles := a.extractJSFiles(string(body), baseURL)

	// 分析每个JS文件
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, a.concurrency)

	for _, jsFile := range jsFiles {
		wg.Add(1)
		go func(file string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			endpoints := a.analyzeJSFile(file)
			a.mutex.Lock()
			a.endpoints = append(a.endpoints, endpoints...)
			a.mutex.Unlock()
		}(jsFile)
	}

	wg.Wait()
	return a.endpoints, nil
}

// extractJSFiles 从HTML中提取JS文件链接
func (a *JSAnalyzer) extractJSFiles(html, baseURL string) []string {
	var jsFiles []string

	// 匹配script标签中的src属性
	scriptRegex := regexp.MustCompile(`<script[^>]*src=["']([^"']+)["'][^>]*>`)
	matches := scriptRegex.FindAllStringSubmatch(html, -1)

	base, _ := url.Parse(baseURL)

	for _, match := range matches {
		if len(match) > 1 {
			jsURL := match[1]
			// 处理相对URL
			if strings.HasPrefix(jsURL, "//") {
				jsURL = "http:" + jsURL
			} else if strings.HasPrefix(jsURL, "/") {
				jsURL = base.Scheme + "://" + base.Host + jsURL
			} else if !strings.HasPrefix(jsURL, "http") {
				jsURL = base.Scheme + "://" + base.Host + "/" + jsURL
			}
			jsFiles = append(jsFiles, jsURL)
		}
	}

	return jsFiles
}

// analyzeJSFile 分析单个JS文件
func (a *JSAnalyzer) analyzeJSFile(jsURL string) []JSEndpoint {
	var endpoints []JSEndpoint

	// 获取JS文件内容
	resp, err := a.client.Get(jsURL)
	if err != nil {
		fmt.Printf(config.ColorRed("[ERROR]")+" Failed to fetch JS file %s: %v\n", jsURL, err)
		return endpoints
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf(config.ColorRed("[ERROR]")+" Failed to read JS file %s: %v\n", jsURL, err)
		return endpoints
	}

	jsContent := string(body)

	// 分析JS内容，提取API端点
	endpoints = append(endpoints, a.extractAJAXCalls(jsContent, jsURL)...)
	endpoints = append(endpoints, a.extractFetchCalls(jsContent, jsURL)...)
	endpoints = append(endpoints, a.extractAxiosCalls(jsContent, jsURL)...)
	endpoints = append(endpoints, a.extractJQueryCalls(jsContent, jsURL)...)
	endpoints = append(endpoints, a.extractXMLHttpRequests(jsContent, jsURL)...)
	endpoints = append(endpoints, a.extractURLPatterns(jsContent, jsURL)...)

	return endpoints
}

// extractAJAXCalls 提取jQuery AJAX调用
func (a *JSAnalyzer) extractAJAXCalls(jsContent, source string) []JSEndpoint {
	var endpoints []JSEndpoint

	// 匹配 $.ajax() 调用
	ajaxRegex := regexp.MustCompile(`\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*["']([^"']+)["'][^}]*\}`)
	matches := ajaxRegex.FindAllStringSubmatch(jsContent, -1)

	for _, match := range matches {
		if len(match) > 1 {
			endpoint := JSEndpoint{
				URL:    match[1],
				Method: "GET", // 默认方法
				Source: source,
			}
			endpoints = append(endpoints, endpoint)
		}
	}

	// 匹配 $.get(), $.post() 等快捷方法
	getRegex := regexp.MustCompile(`\$\.(get|post|put|delete)\s*\(\s*["']([^"']+)["']`)
	getMatches := getRegex.FindAllStringSubmatch(jsContent, -1)

	for _, match := range getMatches {
		if len(match) > 2 {
			method := strings.ToUpper(match[1])
			endpoint := JSEndpoint{
				URL:    match[2],
				Method: method,
				Source: source,
			}
			endpoints = append(endpoints, endpoint)
		}
	}

	return endpoints
}

// extractFetchCalls 提取fetch API调用
func (a *JSAnalyzer) extractFetchCalls(jsContent, source string) []JSEndpoint {
	var endpoints []JSEndpoint

	// 匹配 fetch() 调用
	fetchRegex := regexp.MustCompile(`fetch\s*\(\s*["']([^"']+)["']`)
	matches := fetchRegex.FindAllStringSubmatch(jsContent, -1)

	for _, match := range matches {
		if len(match) > 1 {
			endpoint := JSEndpoint{
				URL:    match[1],
				Method: "GET", // fetch默认是GET
				Source: source,
			}
			endpoints = append(endpoints, endpoint)
		}
	}

	// 匹配带配置的fetch调用
	fetchConfigRegex := regexp.MustCompile(`fetch\s*\(\s*["']([^"']+)["']\s*,\s*\{[^}]*method\s*:\s*["']([^"']+)["']`)
	configMatches := fetchConfigRegex.FindAllStringSubmatch(jsContent, -1)

	for _, match := range configMatches {
		if len(match) > 2 {
			endpoint := JSEndpoint{
				URL:    match[1],
				Method: strings.ToUpper(match[2]),
				Source: source,
			}
			endpoints = append(endpoints, endpoint)
		}
	}

	return endpoints
}

// extractAxiosCalls 提取Axios调用
func (a *JSAnalyzer) extractAxiosCalls(jsContent, source string) []JSEndpoint {
	var endpoints []JSEndpoint

	// 匹配 axios.get(), axios.post() 等
	axiosRegex := regexp.MustCompile(`axios\.(get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']`)
	matches := axiosRegex.FindAllStringSubmatch(jsContent, -1)

	for _, match := range matches {
		if len(match) > 2 {
			method := strings.ToUpper(match[1])
			endpoint := JSEndpoint{
				URL:    match[2],
				Method: method,
				Source: source,
			}
			endpoints = append(endpoints, endpoint)
		}
	}

	// 匹配 axios() 调用
	axiosConfigRegex := regexp.MustCompile(`axios\s*\(\s*\{[^}]*url\s*:\s*["']([^"']+)["'][^}]*method\s*:\s*["']([^"']+)["']`)
	configMatches := axiosConfigRegex.FindAllStringSubmatch(jsContent, -1)

	for _, match := range configMatches {
		if len(match) > 2 {
			endpoint := JSEndpoint{
				URL:    match[1],
				Method: strings.ToUpper(match[2]),
				Source: source,
			}
			endpoints = append(endpoints, endpoint)
		}
	}

	return endpoints
}

// extractJQueryCalls 提取jQuery调用
func (a *JSAnalyzer) extractJQueryCalls(jsContent, source string) []JSEndpoint {
	var endpoints []JSEndpoint

	// 匹配 $.load() 调用
	loadRegex := regexp.MustCompile(`\$\([^)]+\)\.load\s*\(\s*["']([^"']+)["']`)
	matches := loadRegex.FindAllStringSubmatch(jsContent, -1)

	for _, match := range matches {
		if len(match) > 1 {
			endpoint := JSEndpoint{
				URL:    match[1],
				Method: "GET",
				Source: source,
			}
			endpoints = append(endpoints, endpoint)
		}
	}

	return endpoints
}

// extractXMLHttpRequests 提取XMLHttpRequest调用
func (a *JSAnalyzer) extractXMLHttpRequests(jsContent, source string) []JSEndpoint {
	var endpoints []JSEndpoint

	// 匹配 XMLHttpRequest 调用
	xhrRegex := regexp.MustCompile(`\.open\s*\(\s*["']([^"']+)["']\s*,\s*["']([^"']+)["']`)
	matches := xhrRegex.FindAllStringSubmatch(jsContent, -1)

	for _, match := range matches {
		if len(match) > 2 {
			endpoint := JSEndpoint{
				URL:    match[2],
				Method: strings.ToUpper(match[1]),
				Source: source,
			}
			endpoints = append(endpoints, endpoint)
		}
	}

	return endpoints
}

// extractURLPatterns 提取URL模式
func (a *JSAnalyzer) extractURLPatterns(jsContent, source string) []JSEndpoint {
	var endpoints []JSEndpoint

	// 匹配各种URL模式
	urlPatterns := []string{
		`["']([^"']*\/api\/[^"']*)["']`,      // /api/ 路径
		`["']([^"']*\/v[0-9]+\/[^"']*)["']`,  // 版本化API
		`["']([^"']*\/endpoint\/[^"']*)["']`, // /endpoint/ 路径
		`["']([^"']*\/service\/[^"']*)["']`,  // /service/ 路径
		`["']([^"']*\/rest\/[^"']*)["']`,     // /rest/ 路径
		`["']([^"']*\/graphql[^"']*)["']`,    // GraphQL端点
		`["']([^"']*\/soap[^"']*)["']`,       // SOAP端点
		`["']([^"']*\/rpc[^"']*)["']`,        // RPC端点
	}

	for _, pattern := range urlPatterns {
		regex := regexp.MustCompile(pattern)
		matches := regex.FindAllStringSubmatch(jsContent, -1)

		for _, match := range matches {
			if len(match) > 1 {
				endpoint := JSEndpoint{
					URL:    match[1],
					Method: "GET", // 默认方法
					Source: source,
				}
				endpoints = append(endpoints, endpoint)
			}
		}
	}

	return endpoints
}

// PrintEndpoints 打印发现的端点
func (a *JSAnalyzer) PrintEndpoints() {
	if len(a.endpoints) == 0 {
		fmt.Println(config.ColorYellow("[JS-ANALYZER]"), "No API endpoints found in JavaScript files")
		return
	}

	fmt.Printf(config.ColorCyan("[JS-ANALYZER]")+" 发现 %d 个API端点:\n\n", len(a.endpoints))

	for i, endpoint := range a.endpoints {
		fmt.Printf("%d. %s %s\n", i+1, endpoint.Method, endpoint.URL)
		fmt.Printf("   来源: %s\n", endpoint.Source)
		if len(endpoint.Parameters) > 0 {
			fmt.Printf("   参数: %s\n", strings.Join(endpoint.Parameters, ", "))
		}
		if len(endpoint.Headers) > 0 {
			fmt.Printf("   请求头: %v\n", endpoint.Headers)
		}
		if endpoint.Context != "" {
			fmt.Printf("   上下文: %s\n", endpoint.Context)
		}
		fmt.Println()
	}
}

// SaveEndpoints 保存端点到文件
func (a *JSAnalyzer) SaveEndpoints(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// 将端点保存为JSON格式
	jsonData, err := json.MarshalIndent(a.endpoints, "", "  ")
	if err != nil {
		return err
	}

	_, err = file.Write(jsonData)
	return err
}
