package parse

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/proxy"
	"github.com/Gh0xE9/EagleSword/config"
)

// createProxyTransport 创建支持代理的HTTP Transport
func createProxyTransport(proxyURL string) (*http.Transport, error) {
	// 创建基础Transport，跳过TLS证书验证
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	if proxyURL == "" {
		return transport, nil
	}

	// 解析代理URL
	parsedProxyURL, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	// 根据代理类型配置Transport
	switch parsedProxyURL.Scheme {
	case "http", "https":
		transport.Proxy = http.ProxyURL(parsedProxyURL)
	case "socks5":
		// 创建SOCKS5代理dialer
		password, _ := parsedProxyURL.User.Password()
		auth := &proxy.Auth{
			User:     parsedProxyURL.User.Username(),
			Password: password,
		}
		dialer, err := proxy.SOCKS5("tcp", parsedProxyURL.Host, auth, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("failed to create SOCKS5 proxy: %w", err)
		}
		transport.Dial = dialer.Dial
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s (supported: http, https, socks5)", parsedProxyURL.Scheme)
	}

	return transport, nil
}

func ExtractAPIEndpoints(base string, js string) ([]string, error) {
	var out []string
	if js == "" {
		return out, nil
	}

	baseURL, _ := url.Parse(base)
	seen := map[string]struct{}{}

	absRe := regexp.MustCompile(`(?i)(http|ftp|https):\/\/[\w\-_]+(\.[\w\-_]+)+([\w\-\.,@?^=%&:/~\+#]*[\w\-\@?^=%&/~])?`)
	for _, m := range absRe.FindAllString(js, -1) {
		u := strings.TrimSpace(trimQuotes(m))
		if u == "" {
			continue
		}
		u = strings.TrimRight(u, ")],};")
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
	}

	apiRe := regexp.MustCompile(`(?s)['"\x60](\/[a-zA-Z0-9_?&=\/\#\.-]*)['"\x60]`)
	for _, m := range apiRe.FindAllStringSubmatch(js, -1) {
		if len(m) < 2 {
			continue
		}
		raw := strings.TrimSpace(m[1])
		if raw == "" {
			continue
		}
		var abs string
		if baseURL != nil {
			ref, err := url.Parse(raw)
			if err != nil {
				continue
			}
			abs = baseURL.ResolveReference(ref).String()
		} else {
			abs = raw
		}
		if abs == "" {
			continue
		}
		if _, ok := seen[abs]; ok {
			continue
		}
		seen[abs] = struct{}{}
	}

	out = make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	return out, nil
}

func trimQuotes(s string) string {
	s = strings.TrimSpace(s)
	n := len(s)
	if n >= 2 {
		if (s[0] == '"' && s[n-1] == '"') || (s[0] == '\'' && s[n-1] == '\'') {
			return s[1 : n-1]
		}
	}
	return s
}

type PathFinding struct {
	File string
	Path string
	Line int
}

func ExtractPaths(text string) []string {
	if text == "" {
		return nil
	}

	var paths []string
	seen := make(map[string]bool)

	pathRe := regexp.MustCompile(`['"](?:\/|\.\.\/|\.\/)[^\/\>\< \)\(\{\}\,\'\"\\]([^\>\< \)\(\{\}\,\'\"\\])*?['"]`)
	matches := pathRe.FindAllString(text, -1)

	for _, match := range matches {
		if len(match) >= 2 {
			path := match[1 : len(match)-1]
			if !seen[path] {
				paths = append(paths, path)
				seen[path] = true
			}
		}
	}

	return paths
}

type APIResult struct {
	URL      string
	Method   string
	Status   int
	Length   int
	Title    string
	Response string
}

func TestAPIEndpoints(baseURL string, endpoints []string, cookies string, headers map[string]string, proxyURL string) []APIResult {
	var results []APIResult

	// 创建支持代理的Transport
	transport, err := createProxyTransport(proxyURL)
	if err != nil {
		fmt.Printf("Failed to create proxy transport: %v\n", err)
		return results
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   config.HTTPConfig.Timeout,
	}

	for _, endpoint := range endpoints {
		fullURL := buildFullURL(baseURL, endpoint)
		if fullURL == "" {
			continue
		}

		getResult := testAPIEndpoint(client, fullURL, "GET", cookies, headers)
		if getResult != nil {
			results = append(results, *getResult)
		}

		postResult := testAPIEndpoint(client, fullURL, "POST", cookies, headers)
		if postResult != nil {
			results = append(results, *postResult)
		}
	}

	return results
}

func testAPIEndpoint(client *http.Client, url, method, cookies string, headers map[string]string) *APIResult {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", config.RandomUserAgent())

	if cookies != "" {
		req.Header.Set("Cookie", cookies)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	title := extractTitleFromResponse(string(body))

	response := string(body)
	if len(response) > 200 {
		response = response[:200] + "..."
	}

	return &APIResult{
		URL:      url,
		Method:   method,
		Status:   resp.StatusCode,
		Length:   len(body),
		Title:    title,
		Response: response,
	}
}

func buildFullURL(baseURL, endpoint string) string {
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		return endpoint
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}

	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}

	fullURL := base.ResolveReference(endpointURL)
	return fullURL.String()
}

func extractTitleFromResponse(content string) string {
	start := strings.Index(content, "<title>")
	if start == -1 {
		return ""
	}
	start += 7
	end := strings.Index(content[start:], "</title>")
	if end == -1 {
		return ""
	}
	title := strings.TrimSpace(content[start : start+end])

	if len(title) > 50 {
		title = title[:50] + "..."
	}

	return title
}

// OutputAPIResults 输出 API 测试结果
func OutputAPIResults(results []APIResult) {
	for _, result := range results {
		// 限制response长度并去掉换行符，避免换行
		response := result.Response
		// 去掉所有换行符和制表符
		response = strings.ReplaceAll(response, "\n", " ")
		response = strings.ReplaceAll(response, "\r", " ")
		response = strings.ReplaceAll(response, "\t", " ")
		// 压缩多个空格为单个空格
		for strings.Contains(response, "  ") {
			response = strings.ReplaceAll(response, "  ", " ")
		}
		// 限制长度
		if len(response) > 100 {
			response = response[:100] + "..."
		}

		fmt.Printf("%s %s %s %s %s %s %s %s %s %s %s %s %s\n",
			config.ColorCyan("[API]"),
			config.ColorYellow("path:"), config.ColorGreen(result.URL),
			config.ColorYellow("length:"), config.ColorBlue(fmt.Sprintf("%d", result.Length)),
			config.ColorYellow("method:"), config.ColorMagenta(result.Method),
			config.ColorYellow("code:"), config.ColorBlue(fmt.Sprintf("%d", result.Status)),
			config.ColorYellow("response:"), config.ColorRed(response),
			config.ColorYellow("title:"), config.ColorGreen(result.Title))
	}
}

// 颜色输出函数

// ExtractPathsWithFile 从文本中提取所有路径（包含文件名和行号）
func ExtractPathsWithFile(filename string, text string) []PathFinding {
	if text == "" {
		return nil
	}

	var findings []PathFinding
	seen := make(map[string]bool)

	// 格式化 JS 代码
	formattedJS := FormatJS(text)
	lines := strings.Split(formattedJS, "\n")

	// 匹配以 / 开头的路径
	pathRe := regexp.MustCompile(`['"](?:\/|\.\.\/|\.\/)[^\/\>\< \)\(\{\}\,\'\"\\]([^\>\< \)\(\{\}\,\'\"\\])*?['"]`)

	for i, line := range lines {
		matches := pathRe.FindAllString(line, -1)
		for _, match := range matches {
			// 去除首尾的引号
			if len(match) >= 2 {
				path := match[1 : len(match)-1]
				// 去重
				if !seen[path] {
					findings = append(findings, PathFinding{
						File: filename,
						Path: path,
						Line: i + 1,
					})
					seen[path] = true
				}
			}
		}
	}

	return findings
}
