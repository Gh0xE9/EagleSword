package parse

import (
	"regexp"
	"strings"
	"sync"

	"github.com/Gh0xE9/EagleSword/config"
)

// 预编译的正则表达式缓存
var (
	nucleiPatterns     []*regexp.Regexp
	nucleiPatternsOnce sync.Once

	// 预编译的验证正则表达式
	onlyDigitsRegex  = regexp.MustCompile(`^\d+$`)
	onlySpecialRegex = regexp.MustCompile(`^[^a-zA-Z0-9]+$`)
)

// NucleiSensitiveFinding Nuclei 风格的敏感信息发现
type NucleiSensitiveFinding struct {
	Type    string // 类型：token, password, key, secret, function, variable
	Name    string // 变量名或函数名
	Value   string // 值
	Context string // 上下文
	File    string // 文件名
	Line    int    // 行号
	Pattern string // 匹配的模式名称
}

// GetNucleiRegexPatterns 获取 Nuclei 风格的正则表达式模式（使用缓存）
func GetNucleiRegexPatterns() []*regexp.Regexp {
	nucleiPatternsOnce.Do(func() {
		nucleiPatterns = compileNucleiPatterns()
	})
	return nucleiPatterns
}

// compileNucleiPatterns 编译所有 Nuclei 正则表达式
func compileNucleiPatterns() []*regexp.Regexp {
	var patterns []*regexp.Regexp

	// 从 config 包中获取 Nuclei 正则表达式列表
	nucleiRegexStrings := config.NucleiRegexPatterns

	// 编译所有正则表达式
	for _, regexStr := range nucleiRegexStrings {
		patterns = append(patterns, regexp.MustCompile(regexStr))
	}

	return patterns
}

// ExtractNucleiSensitiveFindings 使用 Nuclei 风格的正则表达式提取敏感信息（优化版本）
func ExtractNucleiSensitiveFindings(filename, text string) []NucleiSensitiveFinding {
	// 早期退出：如果文本为空或太短，直接返回
	if len(text) < 10 {
		return []NucleiSensitiveFinding{}
	}

	var findings []NucleiSensitiveFinding

	// 获取所有正则表达式模式（使用缓存）
	patterns := GetNucleiRegexPatterns()

	// 并行处理正则表达式
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 限制并发数，避免过多 goroutine
	maxWorkers := 8
	if len(patterns) < maxWorkers {
		maxWorkers = len(patterns)
	}

	semaphore := make(chan struct{}, maxWorkers)

		for _, pattern := range patterns {
		wg.Add(1)
		go func(p *regexp.Regexp) {
			defer wg.Done()
			semaphore <- struct{}{}        // 获取信号量
			defer func() { <-semaphore }() // 释放信号量

			// 直接在原始文本上搜索，避免格式化开销
			matches := p.FindAllStringSubmatch(text, -1)
			if len(matches) == 0 {
				return
			}

			var patternFindings []NucleiSensitiveFinding
			for _, match := range matches {
				if len(match) == 0 {
					continue
				}

					var value string
					if len(match) > 1 {
						value = match[1]
					} else {
						value = match[0]
					}

				// 快速清理值
					value = strings.Trim(value, `"'`)

				// 快速过滤
				if len(value) < 3 || !isValidSensitiveValue(value) {
						continue
					}

				// 确定类型（缓存结果）
				sensitiveType := determineSensitiveTypeFromPattern(p.String())

					finding := NucleiSensitiveFinding{
						Type:    sensitiveType,
						Name:    "nuclei_pattern",
						Value:   value,
					Context: match[0], // 使用匹配的原始文本作为上下文
						File:    filename,
					Line:    0, // 不计算行号以提高性能
					Pattern: p.String(),
				}

				patternFindings = append(patternFindings, finding)
			}

			// 线程安全地添加结果
			if len(patternFindings) > 0 {
				mu.Lock()
				findings = append(findings, patternFindings...)
				mu.Unlock()
			}
		}(pattern)
	}

	wg.Wait()

	// 去重
	return deduplicateNucleiFindings(findings)
}

// determineSensitiveTypeFromPattern 根据正则表达式模式确定敏感信息类型
func determineSensitiveTypeFromPattern(patternStr string) string {
	patternStrLower := strings.ToLower(patternStr)

	if strings.Contains(patternStrLower, "password") || strings.Contains(patternStrLower, "passwd") || strings.Contains(patternStrLower, "pwd") {
		return "password"
	}
	if strings.Contains(patternStrLower, "username") || strings.Contains(patternStrLower, "user") {
		return "username"
	}
	if strings.Contains(patternStrLower, "token") || strings.Contains(patternStrLower, "bearer") || strings.Contains(patternStrLower, "auth") {
		return "token"
	}
	if strings.Contains(patternStrLower, "secret") {
		return "secret"
	}
	if strings.Contains(patternStrLower, "key") {
		return "key"
	}
	if strings.Contains(patternStrLower, "api") {
		return "api"
	}
	if strings.Contains(patternStrLower, "mysql") || strings.Contains(patternStrLower, "postgres") || strings.Contains(patternStrLower, "database") || strings.Contains(patternStrLower, "db") {
		return "database"
	}
	if strings.Contains(patternStrLower, "webhook") {
		return "webhook"
	}

	return "unknown"
}

// deduplicateNucleiFindings 去重 Nuclei 敏感信息发现
func deduplicateNucleiFindings(findings []NucleiSensitiveFinding) []NucleiSensitiveFinding {
	seen := make(map[string]bool)
	var result []NucleiSensitiveFinding

	for _, finding := range findings {
		// 使用类型+值+文件名作为去重键，避免重复的敏感信息
		key := finding.Type + ":" + finding.Value + ":" + finding.File
		if !seen[key] {
			seen[key] = true
			result = append(result, finding)
		}
	}

	return result
}

// isValidSensitiveValue 快速验证敏感信息值是否有效
func isValidSensitiveValue(value string) bool {
	// 快速长度检查
	if len(value) < 3 || len(value) > 200 {
		return false
	}

	// 快速检查常见无效值
	valueLower := strings.ToLower(value)
	invalidValues := []string{
		"true", "false", "null", "undefined", "function", "object",
		"this", "window", "document", "console", "alert", "log",
		"test", "example", "demo", "sample", "placeholder", "default",
		"admin", "user", "password", "secret", "key", "token",
	}

	for _, invalid := range invalidValues {
		if valueLower == invalid {
			return false
		}
	}

	// 使用预编译的正则表达式
	if onlyDigitsRegex.MatchString(value) {
		return false
	}

	if onlySpecialRegex.MatchString(value) {
		return false
	}

	return true
}
