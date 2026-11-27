package parse

import (
	"regexp"
	"strings"

	"github.com/Gh0xE9/EagleSword/config"
)

// FormatJS 简单的 JS 代码格式化，主要是添加换行和缩进
func FormatJS(js string) string {
	if js == "" {
		return js
	}

	// 基本的格式化规则
	formatted := js

	// 在分号后添加换行
	formatted = regexp.MustCompile(`;`).ReplaceAllString(formatted, ";\n")

	// 在左大括号后添加换行和缩进
	formatted = regexp.MustCompile(`\{`).ReplaceAllString(formatted, "{\n")

	// 在右大括号前添加换行
	formatted = regexp.MustCompile(`\}`).ReplaceAllString(formatted, "\n}")

	// 在逗号后添加换行（但不在字符串内）
	formatted = regexp.MustCompile(`,\s*`).ReplaceAllString(formatted, ",\n")

	// 清理多余的空行
	formatted = regexp.MustCompile(`\n\s*\n\s*\n`).ReplaceAllString(formatted, "\n\n")

	// 移除行首行尾空白
	lines := strings.Split(formatted, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSpace(line)
	}
	formatted = strings.Join(lines, "\n")

	return formatted
}

// ExtractSensitiveFields 返回匹配到的字段名切片
func ExtractSensitiveFields(js string) []string {
	matches := config.SensitiveRe.FindAllStringSubmatch(js, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) >= 3 {
			// m[2] 为字段名分组
			out = append(out, m[2])
		}
	}
	return out
}

// SensitiveFinding 表示一次敏感信息命中（字段名与所在行号，行号从 1 开始）
type SensitiveFinding struct {
	Field string
	Line  int
}

// SensitiveFindingWithFile 表示一次敏感信息命中（包含文件名、字段名与所在行号）
type SensitiveFindingWithFile struct {
	File  string
	Field string
	Line  int
}

// ExtractSensitiveFindings 返回包含行号的匹配结果
func ExtractSensitiveFindings(js string) []SensitiveFinding {
	var out []SensitiveFinding
	if js == "" {
		return out
	}

	// 先格式化 JS 代码
	formattedJS := FormatJS(js)

	lines := strings.Split(formattedJS, "\n")
	for i, line := range lines { // i 从 0 开始，行号为 i+1
		ms := config.SensitiveRe.FindAllStringSubmatch(line, -1)
		if len(ms) == 0 {
			continue
		}
		for _, m := range ms {
			if len(m) >= 3 {
				out = append(out, SensitiveFinding{Field: m[2], Line: i + 1})
			}
		}
	}
	return out
}

// ExtractSensitiveFindingsWithFile 返回包含文件名和行号的匹配结果
func ExtractSensitiveFindingsWithFile(filename string, js string) []SensitiveFindingWithFile {
	var out []SensitiveFindingWithFile
	if js == "" {
		return out
	}

	// 先格式化 JS 代码
	formattedJS := FormatJS(js)

	lines := strings.Split(formattedJS, "\n")
	for i, line := range lines { // i 从 0 开始，行号为 i+1
		ms := config.SensitiveRe.FindAllStringSubmatch(line, -1)
		if len(ms) == 0 {
			continue
		}
		for _, m := range ms {
			if len(m) >= 3 {
				out = append(out, SensitiveFindingWithFile{
					File:  filename,
					Field: m[2],
					Line:  i + 1,
				})
			}
		}
	}
	return out
}
