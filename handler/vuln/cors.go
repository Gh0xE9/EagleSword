package vuln

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
	"github.com/Gh0xE9/EagleSword/config"
)

// CORSCheckResult CORS检测结果
type CORSCheckResult struct {
	URL                           string
	Origin                        string
	AccessControlAllowOrigin      string
	AccessControlAllowMethods     string
	AccessControlAllowHeaders     string
	AccessControlAllowCredentials string
	IsVulnerable                  bool
	VulnerabilityReason           string
}

// CheckCORS 检测CORS漏洞
func CheckCORS(targetURL string, apiEndpoints []string, proxyURL string) (*CORSCheckResult, error) {
	// 创建HTTP客户端
	client := createHTTPClient(proxyURL)

	var bestResult *CORSCheckResult
	var bestVulnerability string

	// 首先检测目标URL本身
	result, err := testCORSEndpoint(client, targetURL, "GET")
	if err == nil && result.IsVulnerable {
		bestResult = result
		bestVulnerability = result.VulnerabilityReason
	}

	// 检测所有API端点
	for _, endpoint := range apiEndpoints {
		fullURL := targetURL + endpoint

		// 测试GET请求
		result, err := testCORSEndpoint(client, fullURL, "GET")
		if err == nil && result.IsVulnerable {
			if bestResult == nil || len(result.VulnerabilityReason) > len(bestVulnerability) {
				bestResult = result
				bestVulnerability = result.VulnerabilityReason
			}
		}

		// 测试POST请求
		result, err = testCORSEndpoint(client, fullURL, "POST")
		if err == nil && result.IsVulnerable {
			if bestResult == nil || len(result.VulnerabilityReason) > len(bestVulnerability) {
				bestResult = result
				bestVulnerability = result.VulnerabilityReason
			}
		}

		// 测试OPTIONS请求（预检请求）
		result, err = testCORSEndpoint(client, fullURL, "OPTIONS")
		if err == nil && result.IsVulnerable {
			if bestResult == nil || len(result.VulnerabilityReason) > len(bestVulnerability) {
				bestResult = result
				bestVulnerability = result.VulnerabilityReason
			}
		}
	}

	if bestResult == nil {
		// 如果没有发现漏洞，返回一个默认结果
		return &CORSCheckResult{
			URL:                           targetURL,
			Origin:                        "https://example.com",
			AccessControlAllowOrigin:      "",
			AccessControlAllowMethods:     "",
			AccessControlAllowHeaders:     "",
			AccessControlAllowCredentials: "",
			IsVulnerable:                  false,
			VulnerabilityReason:           "No CORS vulnerability detected",
		}, nil
	}

	return bestResult, nil
}

// testCORSEndpoint 测试特定端点的CORS配置
func testCORSEndpoint(client *http.Client, url string, method string) (*CORSCheckResult, error) {
	// 创建请求
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// 设置测试Origin
	testOrigin := "https://example.com"
	req.Header.Set("Origin", testOrigin)
	req.Header.Set("User-Agent", config.RandomUserAgent())

	// 为POST请求添加Content-Type
	if method == "POST" {
		req.Header.Set("Content-Type", "application/json")
	}

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// 解析响应头
	result := &CORSCheckResult{
		URL:                           url,
		Origin:                        testOrigin,
		AccessControlAllowOrigin:      resp.Header.Get("Access-Control-Allow-Origin"),
		AccessControlAllowMethods:     resp.Header.Get("Access-Control-Allow-Methods"),
		AccessControlAllowHeaders:     resp.Header.Get("Access-Control-Allow-Headers"),
		AccessControlAllowCredentials: resp.Header.Get("Access-Control-Allow-Credentials"),
		IsVulnerable:                  false,
		VulnerabilityReason:           "",
	}

	// 检查CORS漏洞
	result.IsVulnerable, result.VulnerabilityReason = checkCORSVulnerability(result)

	return result, nil
}

// checkCORSVulnerability 检查CORS漏洞
func checkCORSVulnerability(result *CORSCheckResult) (bool, string) {
	allowOrigin := result.AccessControlAllowOrigin

	// 情况1: Access-Control-Allow-Origin为null
	if allowOrigin == "null" {
		return true, "Access-Control-Allow-Origin is null (trusts any domain)"
	}

	// 情况2: Access-Control-Allow-Origin为*（通配符）
	if allowOrigin == "*" {
		return true, "Access-Control-Allow-Origin is * (allows any domain)"
	}

	// 情况3: Access-Control-Allow-Origin完全匹配测试Origin（Origin反射攻击）
	if allowOrigin == result.Origin {
		return true, "Access-Control-Allow-Origin reflects Origin header (Origin reflection attack)"
	}

	// 情况4: Access-Control-Allow-Origin包含测试Origin（可能存在子域名问题）
	if strings.Contains(allowOrigin, result.Origin) {
		return true, "Access-Control-Allow-Origin contains test origin"
	}

	// 情况5: 检查是否有Access-Control-Allow-Credentials: true
	if result.AccessControlAllowCredentials == "true" && (allowOrigin == "*" || allowOrigin == "null") {
		return true, "Access-Control-Allow-Credentials is true with wildcard/null origin"
	}

	// 情况6: 检查是否有Access-Control-Allow-Credentials: true 配合Origin反射
	if result.AccessControlAllowCredentials == "true" && allowOrigin == result.Origin {
		return true, "Access-Control-Allow-Credentials is true with Origin reflection (high risk)"
	}

	// 情况7: 检查是否有多个Origin值（逗号分隔）
	if strings.Contains(allowOrigin, ",") {
		origins := strings.Split(allowOrigin, ",")
		for _, origin := range origins {
			if strings.TrimSpace(origin) == result.Origin {
				return true, "Access-Control-Allow-Origin contains test origin in comma-separated list"
			}
		}
	}

	return false, "No CORS vulnerability detected"
}

// OutputCORSResult 输出CORS检测结果
func OutputCORSResult(result *CORSCheckResult) {
	if result.IsVulnerable {
		fmt.Printf("%s Origin:%s Access-Control-Allow-Origin:%s vuln:yes\n",
			config.ColorRed("[CORS]"),
			config.ColorYellow(result.Origin),
			config.ColorRed(result.AccessControlAllowOrigin))
	} else {
		fmt.Printf("%s Origin:%s Access-Control-Allow-Origin:%s vuln:no\n",
			config.ColorCyan("[CORS]"),
			config.ColorYellow(result.Origin),
			config.ColorGreen(result.AccessControlAllowOrigin))
	}
}

// createHTTPClient 创建HTTP客户端
func createHTTPClient(proxyURL string) *http.Client {
	// 创建基础Transport，跳过TLS证书验证
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	if proxyURL != "" {
		// 解析代理URL
		parsedProxyURL, err := url.Parse(proxyURL)
		if err == nil {
			// 根据代理类型配置Transport
			switch parsedProxyURL.Scheme {
			case "http", "https":
				transport.Proxy = http.ProxyURL(parsedProxyURL)
			case "socks5":
				// SOCKS5代理处理
				password, _ := parsedProxyURL.User.Password()
				auth := &proxy.Auth{
					User:     parsedProxyURL.User.Username(),
					Password: password,
				}
				dialer, err := proxy.SOCKS5("tcp", parsedProxyURL.Host, auth, proxy.Direct)
				if err == nil {
					transport.Dial = dialer.Dial
				}
			}
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   config.HTTPConfig.Timeout,
	}
}

// FeishuMessage 飞书消息结构
type FeishuMessage struct {
	MsgType string `json:"msg_type"`
	Content struct {
		Text string `json:"text"`
	} `json:"content"`
}

// SendCORSFeishuNotification 发送CORS漏洞飞书通知
func SendCORSFeishuNotification(result *CORSCheckResult) error {
	// 获取飞书 webhook URL
	webhookURL, err := config.GetFeishuWebhook()
	if err != nil {
		return fmt.Errorf("获取飞书 webhook 失败: %w", err)
	}

	message := buildCORSNotificationMessage(result)

	// 创建飞书消息
	feishuMsg := FeishuMessage{
		MsgType: "text",
		Content: struct {
			Text string `json:"text"`
		}{
			Text: message,
		},
	}

	// 转换为 JSON
	jsonData, err := json.Marshal(feishuMsg)
	if err != nil {
		return fmt.Errorf("序列化消息失败: %w", err)
	}

	// 发送 HTTP 请求
	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("发送飞书消息失败: %w", err)
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("飞书消息发送失败，状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}

	return nil
}

// buildCORSNotificationMessage 构建CORS漏洞通知消息
func buildCORSNotificationMessage(result *CORSCheckResult) string {
	var message strings.Builder

	message.WriteString("CORS漏洞检测结果\n")
	message.WriteString("==================\n")
	message.WriteString(fmt.Sprintf("目标URL: %s\n", result.URL))
	message.WriteString(fmt.Sprintf("测试Origin: %s\n", result.Origin))
	message.WriteString(fmt.Sprintf("Access-Control-Allow-Origin: %s\n", result.AccessControlAllowOrigin))
	message.WriteString(fmt.Sprintf("Access-Control-Allow-Methods: %s\n", result.AccessControlAllowMethods))
	message.WriteString(fmt.Sprintf("Access-Control-Allow-Headers: %s\n", result.AccessControlAllowHeaders))
	message.WriteString(fmt.Sprintf("Access-Control-Allow-Credentials: %s\n", result.AccessControlAllowCredentials))
	message.WriteString(fmt.Sprintf("漏洞状态: %s\n", func() string {
		if result.IsVulnerable {
			return "存在漏洞"
		}
		return "无漏洞"
	}()))
	message.WriteString(fmt.Sprintf("漏洞原因: %s\n", result.VulnerabilityReason))
	message.WriteString(fmt.Sprintf("检测时间: %s\n", time.Now().Format("2006-01-02 15:04:05")))

	return message.String()
}
