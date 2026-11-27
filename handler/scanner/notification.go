package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Gh0xE9/EagleSword/config"
	"github.com/Gh0xE9/EagleSword/handler/parse"
)

// FeishuMessage 飞书消息结构
type FeishuMessage struct {
	MsgType string `json:"msg_type"`
	Content struct {
		Text string `json:"text"`
	} `json:"content"`
}

// FeishuMarkdownMessage 飞书 Markdown 消息结构
type FeishuMarkdownMessage struct {
	MsgType string `json:"msg_type"`
	Content struct {
		Text string `json:"text"`
	} `json:"content"`
}

// ScanResult 扫描结果结构
type ScanResult struct {
	TargetURL       string
	APIEndpoints    int
	SSRFEndpoints   int
	SecretCount     int
	SpiderCount     int
	URLCount        int
	DomainCount     int
	IPCount         int
	EmailCount      int
	MobileCount     int
	HasJSMAP        bool
	JSFileCount     int
	JSMAPFileCount  int
	SuccessRequests []APISuccessRequest
}

// APISuccessRequest 成功的 API 请求
type APISuccessRequest struct {
	Title    string
	Length   int
	Method   string
	Response string
	Path     string
}

// SendFeishuNotification 发送飞书通知
func SendFeishuNotification(result *ScanResult) error {
	// 获取飞书 webhook URL
	webhookURL, err := config.GetFeishuWebhook()
	if err != nil {
		return fmt.Errorf("获取飞书 webhook 失败: %w", err)
	}

	message := buildNotificationMessage(result)

	// 创建飞书消息
	feishuMsg := FeishuMarkdownMessage{
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
		return fmt.Errorf("发送飞书通知失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// 读取响应体以获取更多错误信息
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("飞书通知发送失败，状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}

	return nil
}

// buildNotificationMessage 构建纯文本格式的通知消息
func buildNotificationMessage(result *ScanResult) string {
	var message strings.Builder

	message.WriteString("EagleSword 扫描报告\n\n")
	message.WriteString("扫描概览\n")
	message.WriteString(fmt.Sprintf("目标站点: %s\n", result.TargetURL))
	message.WriteString(fmt.Sprintf("扫描时间: %s\n\n", getCurrentTime()))

	message.WriteString("扫描统计\n")
	message.WriteString(fmt.Sprintf("API端点: %d\n", result.APIEndpoints))
	message.WriteString(fmt.Sprintf("SSRF端点: %d\n", result.SSRFEndpoints))
	message.WriteString(fmt.Sprintf("敏感信息: %d\n", result.SecretCount))
	message.WriteString(fmt.Sprintf("爬虫信息: %d\n", result.SpiderCount))
	message.WriteString(fmt.Sprintf("URL地址: %d\n", result.URLCount))
	message.WriteString(fmt.Sprintf("域名: %d\n", result.DomainCount))
	message.WriteString(fmt.Sprintf("IP地址: %d\n", result.IPCount))
	message.WriteString(fmt.Sprintf("邮箱: %d\n", result.EmailCount))
	message.WriteString(fmt.Sprintf("手机号: %d\n", result.MobileCount))
	message.WriteString(fmt.Sprintf("JS文件: %d\n", result.JSFileCount))
	message.WriteString(fmt.Sprintf("JSMAP文件: %d\n", result.JSMAPFileCount))

	// JSMAP 信息泄露检测
	jsmapStatus := "否"
	if result.HasJSMAP {
		jsmapStatus = "是"
	}
	message.WriteString(fmt.Sprintf("JSMAP泄露: %s\n\n", jsmapStatus))

	if len(result.SuccessRequests) > 0 {
		message.WriteString("成功访问的API端点\n")
		for _, req := range result.SuccessRequests {
			// 限制响应内容输出长度为10个字符
			response := req.Response
			if len(response) > 10 {
				response = response[:10] + "..."
			}
			message.WriteString(fmt.Sprintf("路径: %s | 方法: %s | 长度: %d | 响应: %s\n",
				req.Path, req.Method, req.Length, response))
		}
		message.WriteString("\n")
	}

	// 添加风险等级评估
	message.WriteString("风险等级评估\n")
	riskLevel := calculateRiskLevel(result)
	message.WriteString(fmt.Sprintf("风险等级: %s\n\n", riskLevel))

	message.WriteString("---\n")
	message.WriteString("报告生成时间: " + getCurrentTime())

	return message.String()
}

// CreateScanResult 从扫描数据创建扫描结果
func CreateScanResult(targetURL string, data *parse.ExtractResult, apiResults []parse.APIResult, spiderResult *SpiderResult) *ScanResult {
	result := &ScanResult{
		TargetURL: targetURL,
	}

	if data != nil {
		result.APIEndpoints = len(data.Path)
		result.SSRFEndpoints = len(data.PathFindings)
		result.SecretCount = len(data.SecretFindings)
		result.URLCount = len(data.URL)
		result.DomainCount = len(data.Domain)
		result.IPCount = len(data.IP)
		result.EmailCount = len(data.Mail)
		result.MobileCount = len(data.Mobile)
	}

	if spiderResult != nil {
		result.SpiderCount = len(spiderResult.URLs)
	}

	// 统计JS和JSMAP文件数量
	result.JSFileCount = countJSFiles(targetURL)
	result.JSMAPFileCount = countJSMAPFiles(targetURL)

	// 检测 JSMAP 信息泄露
	result.HasJSMAP = checkJSMAPLeakage(targetURL)

	// 处理 API 结果
	for _, apiResult := range apiResults {
		if apiResult.Status == 200 {
			successReq := APISuccessRequest{
				Title:    apiResult.Title,
				Length:   apiResult.Length,
				Method:   apiResult.Method,
				Response: apiResult.Response,
				Path:     apiResult.URL,
			}
			result.SuccessRequests = append(result.SuccessRequests, successReq)
		}
	}

	return result
}

// checkJSMAPLeakage 检测是否存在 JSMAP 信息泄露
func checkJSMAPLeakage(targetURL string) bool {
	// 解析 URL 获取主机名
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return false
	}

	// 构建输出目录路径
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	jsmapDir := fmt.Sprintf("output/%s_%s_%s/jsmap", parsed.Scheme, host, port)

	// 检查 jsmap 目录是否存在且不为空
	if _, err := os.Stat(jsmapDir); os.IsNotExist(err) {
		return false
	}

	// 检查目录中是否有 .map 文件
	files, err := os.ReadDir(jsmapDir)
	if err != nil {
		return false
	}

	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".map") {
			return true
		}
	}

	return false
}

// getCurrentTime 获取当前时间字符串
func getCurrentTime() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

// calculateRiskLevel 计算风险等级
func calculateRiskLevel(result *ScanResult) string {
	riskScore := 0

	// 根据各项指标计算风险分数
	if result.SecretCount > 0 {
		riskScore += result.SecretCount * 3 // 敏感信息权重最高
	}
	if result.SSRFEndpoints > 0 {
		riskScore += result.SSRFEndpoints * 2 // SSRF风险较高
	}
	if result.HasJSMAP {
		riskScore += 5 // JSMAP泄露风险
	}
	if result.APIEndpoints > 10 {
		riskScore += 2 // API端点过多可能增加攻击面
	}

	// 根据分数确定风险等级
	switch {
	case riskScore >= 20:
		return "高危"
	case riskScore >= 10:
		return "中危"
	case riskScore >= 5:
		return "低危"
	default:
		return "安全"
	}
}

// countJSFiles 统计JS文件数量
func countJSFiles(targetURL string) int {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return 0
	}

	// 构建输出目录路径
	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		if parsedURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	outputDir := fmt.Sprintf("output/%s_%s_%s/js", parsedURL.Scheme, host, port)

	// 检查目录是否存在
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		return 0
	}

	// 读取目录中的文件
	files, err := os.ReadDir(outputDir)
	if err != nil {
		return 0
	}

	count := 0
	for _, file := range files {
		if !file.IsDir() && (strings.HasSuffix(file.Name(), ".js") || strings.HasSuffix(file.Name(), ".js.map")) {
			count++
		}
	}

	return count
}

// countJSMAPFiles 统计JSMAP文件数量
func countJSMAPFiles(targetURL string) int {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return 0
	}

	// 构建输出目录路径
	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		if parsedURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	outputDir := fmt.Sprintf("output/%s_%s_%s/jsmap", parsedURL.Scheme, host, port)

	// 检查目录是否存在
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		return 0
	}

	// 读取目录中的文件
	files, err := os.ReadDir(outputDir)
	if err != nil {
		return 0
	}

	count := 0
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".js.map") {
			count++
		}
	}

	return count
}
