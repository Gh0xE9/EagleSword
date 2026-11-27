package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	logFile  *os.File
	logMutex sync.Mutex
	logPath  string
)

// InitLogger 初始化日志记录器
func InitLogger(targetURL string) error {
	logMutex.Lock()
	defer logMutex.Unlock()

	// 创建日志文件名：目标域名_时间戳.log
	parsedURL, err := parseURL(targetURL)
	if err != nil {
		return fmt.Errorf("解析URL失败: %w", err)
	}

	timestamp := time.Now().Format("20060102_150405")
	logFileName := fmt.Sprintf("%s_%s.log", parsedURL.Host, timestamp)

	// 确保output目录存在
	outputDir := "output"
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}

	logPath = filepath.Join(outputDir, logFileName)

	// 创建或打开日志文件
	logFile, err = os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("创建日志文件失败: %w", err)
	}

	// 写入日志头
	logHeader := "=== EagleSword 扫描日志 ===\n"
	logHeader += fmt.Sprintf("目标: %s\n", targetURL)
	logHeader += fmt.Sprintf("开始时间: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	logHeader += "================================\n\n"

	if _, err := logFile.WriteString(logHeader); err != nil {
		return fmt.Errorf("写入日志头失败: %w", err)
	}

	return nil
}

// LogInfo 记录信息日志
func LogInfo(message string, args ...interface{}) {
	logMutex.Lock()
	defer logMutex.Unlock()

	if logFile == nil {
		return
	}

	timestamp := time.Now().Format("15:04:05")
	logMessage := fmt.Sprintf("[%s] [INFO] %s\n", timestamp, fmt.Sprintf(message, args...))
	logFile.WriteString(logMessage)
	logFile.Sync()
}

// LogWarning 记录警告日志
func LogWarning(message string, args ...interface{}) {
	logMutex.Lock()
	defer logMutex.Unlock()

	if logFile == nil {
		return
	}

	timestamp := time.Now().Format("15:04:05")
	logMessage := fmt.Sprintf("[%s] [WARN] %s\n", timestamp, fmt.Sprintf(message, args...))
	logFile.WriteString(logMessage)
	logFile.Sync()
}

// LogError 记录错误日志
func LogError(message string, args ...interface{}) {
	logMutex.Lock()
	defer logMutex.Unlock()

	if logFile == nil {
		return
	}

	timestamp := time.Now().Format("15:04:05")
	logMessage := fmt.Sprintf("[%s] [ERROR] %s\n", timestamp, fmt.Sprintf(message, args...))
	logFile.WriteString(logMessage)
	logFile.Sync()
}

// LogHTTP 记录HTTP请求日志
func LogHTTP(method, url string, statusCode int, responseLength int, userAgent string) {
	logMutex.Lock()
	defer logMutex.Unlock()

	if logFile == nil {
		return
	}

	timestamp := time.Now().Format("15:04:05")
	logMessage := fmt.Sprintf("[%s] [HTTP] %s %s -> %d (%d bytes) [%s]\n",
		timestamp, method, url, statusCode, responseLength, userAgent)
	logFile.WriteString(logMessage)
	logFile.Sync()
}

// LogAPI 记录API端点发现日志
func LogAPI(endpoint string, method string, statusCode int) {
	logMutex.Lock()
	defer logMutex.Unlock()

	if logFile == nil {
		return
	}

	timestamp := time.Now().Format("15:04:05")
	logMessage := fmt.Sprintf("[%s] [API] 发现端点: %s %s (状态码: %d)\n",
		timestamp, method, endpoint, statusCode)
	logFile.WriteString(logMessage)
	logFile.Sync()
}

// LogSecret 记录敏感信息发现日志
func LogSecret(secretType, value, file string, line int) {
	logMutex.Lock()
	defer logMutex.Unlock()

	if logFile == nil {
		return
	}

	timestamp := time.Now().Format("15:04:05")
	logMessage := fmt.Sprintf("[%s] [SECRET] 发现敏感信息: %s -> %s (文件: %s:%d)\n",
		timestamp, secretType, value, file, line)
	logFile.WriteString(logMessage)
	logFile.Sync()
}

// LogSSRF 记录SSRF端点发现日志
func LogSSRF(endpoint, file string, line int) {
	logMutex.Lock()
	defer logMutex.Unlock()

	if logFile == nil {
		return
	}

	timestamp := time.Now().Format("15:04:05")
	logMessage := fmt.Sprintf("[%s] [SSRF] 发现SSRF端点: %s (文件: %s:%d)\n",
		timestamp, endpoint, file, line)
	logFile.WriteString(logMessage)
	logFile.Sync()
}

// LogSpider 记录爬虫发现日志
func LogSpider(url string, statusCode int) {
	logMutex.Lock()
	defer logMutex.Unlock()

	if logFile == nil {
		return
	}

	timestamp := time.Now().Format("15:04:05")
	logMessage := fmt.Sprintf("[%s] [SPIDER] 爬取URL: %s (状态码: %d)\n",
		timestamp, url, statusCode)
	logFile.WriteString(logMessage)
	logFile.Sync()
}

// LogDirectory 记录目录探测日志
func LogDirectory(url, title string, length int, response string) {
	logMutex.Lock()
	defer logMutex.Unlock()

	if logFile == nil {
		return
	}

	timestamp := time.Now().Format("15:04:05")
	logMessage := fmt.Sprintf("[%s] [DIRECTORY] 发现目录: %s (标题: %s, 长度: %d)\n",
		timestamp, url, title, length)
	logFile.WriteString(logMessage)
	logFile.Sync()
}

// LogSummary 记录扫描总结日志
func LogSummary(summary string) {
	logMutex.Lock()
	defer logMutex.Unlock()

	if logFile == nil {
		return
	}

	timestamp := time.Now().Format("15:04:05")
	logMessage := fmt.Sprintf("[%s] [SUMMARY] %s\n", timestamp, summary)
	logFile.WriteString(logMessage)
	logFile.Sync()
}

// CloseLogger 关闭日志记录器
func CloseLogger() {
	logMutex.Lock()
	defer logMutex.Unlock()

	if logFile != nil {
		// 写入结束标记
		endTime := time.Now().Format("2006-01-02 15:04:05")
		logFile.WriteString("\n================================\n")
		logFile.WriteString(fmt.Sprintf("扫描结束时间: %s\n", endTime))
		logFile.WriteString(fmt.Sprintf("日志文件: %s\n", logPath))
		logFile.WriteString("================================\n")

		logFile.Close()
		logFile = nil
	}
}

// GetLogPath 获取当前日志文件路径
func GetLogPath() string {
	return logPath
}

// parseURL 解析URL获取主机名
func parseURL(url string) (*struct{ Host string }, error) {
	// 简单的URL解析，提取主机名
	if len(url) < 8 {
		return nil, fmt.Errorf("无效的URL")
	}

	// 移除协议前缀
	if url[:7] == "http://" {
		url = url[7:]
	} else if url[:8] == "https://" {
		url = url[8:]
	}

	// 查找第一个斜杠
	slashIndex := -1
	for i, char := range url {
		if char == '/' {
			slashIndex = i
			break
		}
	}

	var host string
	if slashIndex == -1 {
		host = url
	} else {
		host = url[:slashIndex]
	}

	// 移除端口号
	colonIndex := -1
	for i, char := range host {
		if char == ':' {
			colonIndex = i
			break
		}
	}

	if colonIndex != -1 {
		host = host[:colonIndex]
	}

	return &struct{ Host string }{Host: host}, nil
}
