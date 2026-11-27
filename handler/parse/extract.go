package parse

import (
	"regexp"
	"strings"
	"sync"

	"github.com/Gh0xE9/EagleSword/config"
)

// 预编译的正则表达式缓存
var (
	extractRegexCache     map[string]*regexp.Regexp
	extractRegexCacheOnce sync.Once
)

// getExtractRegex 获取预编译的正则表达式
func getExtractRegex(patternName string) *regexp.Regexp {
	extractRegexCacheOnce.Do(func() {
		extractRegexCache = make(map[string]*regexp.Regexp)
		for name, pattern := range config.ExtractRegexPatterns {
			extractRegexCache[name] = regexp.MustCompile(pattern)
		}
	})
	return extractRegexCache[patternName]
}

// ExtractResult 数据提取结果
type ExtractResult struct {
	SFZ            []string        // 身份证号
	Mobile         []string        // 手机号
	Mail           []string        // 邮箱
	IP             []string        // IP地址
	IPPort         []string        // IP:端口
	Domain         []string        // 域名
	Path           []string        // 路径
	IncompletePath []string        // 不完整路径
	URL            []string        // URL
	JWT            []string        // JWT Token
	Algorithm      []string        // 加密算法
	Secret         []string        // 密钥
	SecretFindings []SecretFinding // 带文件信息的密钥
	PathFindings   []PathFinding   // 带文件信息的路径
}

// ExtractAllData 从文本中提取所有类型的数据
func ExtractAllData(text string) *ExtractResult {
	if text == "" {
		return &ExtractResult{}
	}

	result := &ExtractResult{
		SFZ:            extractSFZ(text),
		Mobile:         extractMobile(text),
		Mail:           extractMail(text),
		IP:             extractIP(text),
		IPPort:         extractIPPort(text),
		Domain:         extractDomain(text),
		Path:           ExtractPaths(text),
		IncompletePath: extractIncompletePath(text),
		URL:            extractURL(text),
		JWT:            extractJWT(text),
		Algorithm:      extractAlgorithm(text),
		Secret:         extractSecret(text),
		SecretFindings: []SecretFinding{}, // 这里需要文件名，所以暂时为空
		PathFindings:   []PathFinding{},   // 这里需要文件名，所以暂时为空
	}

	// 从 URL 中提取额外的 IP 和域名
	if len(result.URL) > 0 {
		for _, url := range result.URL {
			// 从 URL 中提取 IP
			ips := extractIPFromText(url)
			result.IP = appendUnique(result.IP, ips...)

			// 从 URL 中提取 IP:端口
			ipPorts := extractIPPortFromText(url)
			result.IPPort = appendUnique(result.IPPort, ipPorts...)

			// 从 URL 中提取域名
			domains := extractDomainFromText(url)
			result.Domain = appendUnique(result.Domain, domains...)
		}
	}

	return result
}

// extractSFZ 提取身份证号
func extractSFZ(text string) []string {
	re := getExtractRegex("SFZ")
	matches := re.FindAllString(text, -1)
	return cleanMatches(matches)
}

// extractMobile 提取手机号
func extractMobile(text string) []string {
	re := getExtractRegex("Mobile")
	matches := re.FindAllString(text, -1)
	return cleanMatches(matches)
}

// extractMail 提取邮箱
func extractMail(text string) []string {
	re := getExtractRegex("Mail")
	matches := re.FindAllString(text, -1)

	var filtered []string
	for _, match := range matches {
		// 检查是否有引号，如果有则去除首尾的引号
		var email string
		if len(match) >= 2 && ((match[0] == '"' && match[len(match)-1] == '"') || (match[0] == '\'' && match[len(match)-1] == '\'')) {
			email = match[1 : len(match)-1]
		} else {
			email = match
		}

		// 过滤掉文件扩展名
		if !isFileExtension(email) {
			filtered = append(filtered, email)
		}
	}

	return filtered
}

// isFileExtension 检查是否是文件扩展名
func isFileExtension(email string) bool {
	// 检查是否以常见的文件扩展名结尾
	fileExtensions := []string{".js", ".css", ".jpg", ".jpeg", ".png", ".ico", ".gif", ".svg", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".zip", ".rar"}

	for _, ext := range fileExtensions {
		if strings.HasSuffix(strings.ToLower(email), ext) {
			return true
		}
	}

	return false
}

// extractIP 提取IP地址
func extractIP(text string) []string {
	re := getExtractRegex("IP")
	matches := re.FindAllString(text, -1)
	return cleanMatches(matches)
}

// extractIPPort 提取IP:端口
func extractIPPort(text string) []string {
	re := getExtractRegex("IPPort")
	matches := re.FindAllString(text, -1)
	return cleanMatches(matches)
}

// extractDomain 提取域名
func extractDomain(text string) []string {
	re := getExtractRegex("Domain")
	matches := re.FindAllString(text, -1)
	return cleanMatches(matches)
}

// extractIncompletePath 提取不完整路径
func extractIncompletePath(text string) []string {
	re := getExtractRegex("IncompletePath")
	matches := re.FindAllString(text, -1)
	return cleanMatches(matches)
}

// extractURL 提取URL
func extractURL(text string) []string {
	re := getExtractRegex("URL")
	matches := re.FindAllString(text, -1)
	return cleanMatches(matches)
}

// extractJWT 提取JWT Token
func extractJWT(text string) []string {
	re := getExtractRegex("JWT")
	matches := re.FindAllString(text, -1)
	return cleanMatches(matches)
}

// extractAlgorithm 提取加密算法
func extractAlgorithm(text string) []string {
	re := getExtractRegex("Algorithm")
	matches := re.FindAllString(text, -1)
	return cleanMatches(matches)
}

// SecretFinding 表示密钥发现（包含文件名、字段名和行号）
type SecretFinding struct {
	File  string
	Field string
	Line  int
}

// ExtractSecretFindings 提取密钥发现（包含文件名和行号）
func ExtractSecretFindings(filename string, text string) []SecretFinding {
	var findings []SecretFinding

	// 使用 Nuclei 敏感信息提取
	nucleiFindings := ExtractNucleiSensitiveFindings(filename, text)

	// 用于去重的 map
	seen := make(map[string]bool)

	// 添加 Nuclei 发现
	for _, finding := range nucleiFindings {
		// 创建去重键：类型+值+文件名
		dedupKey := finding.Type + ":" + finding.Value + ":" + finding.File

		// 如果已经存在，跳过
		if seen[dedupKey] {
			continue
		}
		seen[dedupKey] = true

		secretFinding := SecretFinding{
			File:  finding.File,
			Field: finding.Type + ":" + finding.Value,
			Line:  finding.Line,
		}
		findings = append(findings, secretFinding)
	}

	return findings
}

// extractSecret 提取密钥（使用现有的敏感信息提取）
func extractSecret(text string) []string {
	findings := ExtractSensitiveFindings(text)
	var secrets []string
	for _, finding := range findings {
		secrets = append(secrets, finding.Field)
	}
	return secrets
}

// 辅助函数：从文本中提取IP（用于URL处理）
func extractIPFromText(text string) []string {
	re := getExtractRegex("IPFromText")
	matches := re.FindAllString(text, -1)
	return cleanMatches(matches)
}

// 辅助函数：从文本中提取IP:端口（用于URL处理）
func extractIPPortFromText(text string) []string {
	re := getExtractRegex("IPPortFromText")
	matches := re.FindAllString(text, -1)
	return cleanMatches(matches)
}

// 辅助函数：从文本中提取域名（用于URL处理）
func extractDomainFromText(text string) []string {
	re := getExtractRegex("DomainFromText")
	matches := re.FindAllString(text, -1)
	return cleanMatches(matches)
}

// cleanMatches 清理匹配结果，去除引号并去重
func cleanMatches(matches []string) []string {
	var cleaned []string
	seen := make(map[string]bool)

	for _, match := range matches {
		// 检查是否有引号，如果有则去除首尾的引号
		var clean string
		if len(match) >= 2 && ((match[0] == '"' && match[len(match)-1] == '"') || (match[0] == '\'' && match[len(match)-1] == '\'')) {
			clean = match[1 : len(match)-1]
		} else {
			clean = match
		}
		// 去重
		if !seen[clean] && clean != "" {
			cleaned = append(cleaned, clean)
			seen[clean] = true
		}
	}
	return cleaned
}

// appendUnique 添加唯一元素到切片
func appendUnique(slice []string, elements ...string) []string {
	seen := make(map[string]bool)
	result := slice

	for _, elem := range slice {
		seen[elem] = true
	}

	for _, elem := range elements {
		if !seen[elem] {
			seen[elem] = true
			result = append(result, elem)
		}
	}

	return result
}
