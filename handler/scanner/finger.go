package scanner

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed fingerprints.json
var fingerprintsData []byte

// Fingerprint 指纹结构体 (JSON格式)
type Fingerprint struct {
	ID   string `json:"id"`
	Info struct {
		Name     string `json:"name"`
		Author   string `json:"author"`
		Tags     string `json:"tags"`
		Severity string `json:"severity"`
		Metadata struct {
			Product string `json:"product"`
			Vendor  string `json:"vendor"`
		} `json:"metadata"`
	} `json:"info"`
	HTTP []struct {
		Method   string   `json:"method"`
		Path     []string `json:"path"`
		Matchers []struct {
			Type            string   `json:"type"`
			Words           []string `json:"words,omitempty"`
			CaseInsensitive bool     `json:"case-insensitive,omitempty"`
			Condition       string   `json:"condition,omitempty"` // and/or
			Part            string   `json:"part,omitempty"`      // header/body
		} `json:"matchers"`
	} `json:"http"`
}

// FingerprintResult 指纹匹配结果
type FingerprintResult struct {
	Name     string
	Product  string
	Vendor   string
	Severity string
}

// LoadFingerprints 加载嵌入的指纹数据
func LoadFingerprints() ([]Fingerprint, error) {
	var fingerprints []Fingerprint
	err := json.Unmarshal(fingerprintsData, &fingerprints)
	if err != nil {
		return nil, fmt.Errorf("解析指纹JSON失败: %v", err)
	}

	return fingerprints, nil
}

// MatchFingerprints 匹配指纹（使用已解析的数据）
func MatchFingerprints(targetURL string, responseText string, responseHeaders string, fingerprints []Fingerprint) []FingerprintResult {
	var results []FingerprintResult

	// 遍历所有指纹规则
	for _, fingerprint := range fingerprints {
		// 遍历HTTP请求规则
		for _, httpRule := range fingerprint.HTTP {
			// 检查匹配器（使用已解析的数据）
			if matchMatchers(responseText, responseHeaders, httpRule.Matchers) {
				result := FingerprintResult{
					Name:     fingerprint.Info.Name,
					Product:  fingerprint.Info.Metadata.Product,
					Vendor:   fingerprint.Info.Metadata.Vendor,
					Severity: fingerprint.Info.Severity,
				}
				results = append(results, result)

				// 输出匹配结果 - 使用新的格式和颜色
				fmt.Printf("\x1b[36m[FINGER]\x1b[0m \x1b[33mname:\x1b[0m\x1b[34m[%s,%s]<%s>\x1b[0m \x1b[33mtype:\x1b[0m\x1b[35m%s\x1b[0m \x1b[33mcode:\x1b[0m\x1b[32m200\x1b[0m\n",
					fingerprint.Info.Metadata.Product,
					fingerprint.Info.Metadata.Vendor,
					fingerprint.Info.Name,
					fingerprint.Info.Severity)

				// 找到一个匹配就跳出，避免重复
				break
			}
		}
	}

	return results
}

// matchMatchers 检查匹配器
func matchMatchers(responseText string, responseHeaders string, matchers []struct {
	Type            string   `json:"type"`
	Words           []string `json:"words,omitempty"`
	CaseInsensitive bool     `json:"case-insensitive,omitempty"`
	Condition       string   `json:"condition,omitempty"` // and/or
	Part            string   `json:"part,omitempty"`      // header/body
}) bool {
	// 如果没有匹配器，返回false
	if len(matchers) == 0 {
		return false
	}

	// 默认条件为or
	condition := "or"
	if len(matchers) > 0 && matchers[0].Condition != "" {
		condition = matchers[0].Condition
	}

	if condition == "and" {
		// 所有匹配器都必须匹配成功
		for _, matcher := range matchers {
			if !matchSingleMatcher(responseText, responseHeaders, matcher) {
				return false
			}
		}
		return true
	} else {
		// 任何一个匹配器匹配成功就返回true
		for _, matcher := range matchers {
			if matchSingleMatcher(responseText, responseHeaders, matcher) {
				return true
			}
		}
		return false
	}
}

// matchSingleMatcher 匹配单个匹配器
func matchSingleMatcher(responseText string, responseHeaders string, matcher struct {
	Type            string   `json:"type"`
	Words           []string `json:"words,omitempty"`
	CaseInsensitive bool     `json:"case-insensitive,omitempty"`
	Condition       string   `json:"condition,omitempty"`
	Part            string   `json:"part,omitempty"`
}) bool {
	// 确定匹配的文本内容
	text := responseText
	if matcher.Part == "header" {
		text = responseHeaders
	}

	switch matcher.Type {
	case "word":
		return matchWords(text, matcher.Words, matcher.CaseInsensitive)
	default:
		return false
	}
}

// matchWords 关键词匹配
func matchWords(text string, words []string, caseInsensitive bool) bool {
	if len(words) == 0 {
		return false
	}

	if caseInsensitive {
		text = strings.ToLower(text)
	}

	for _, word := range words {
		searchWord := word
		if caseInsensitive {
			searchWord = strings.ToLower(word)
		}

		if strings.Contains(text, searchWord) {
			return true
		}
	}
	return false
}
