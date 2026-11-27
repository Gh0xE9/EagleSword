package parse

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// ParameterInfo 参数信息
type ParameterInfo struct {
	Name     string // 参数名
	Value    string // 参数值
	Location string // 参数位置: url, post, json
	Type     string // 参数类型: string, number, boolean, array, object
}

// RequestInfo 请求信息
type RequestInfo struct {
	URL        string
	Method     string
	Headers    map[string]string
	PostData   string
	JSONData   string
	Parameters []ParameterInfo
}

// ParameterParser 参数解析器
type ParameterParser struct{}

// NewParameterParser 创建新的参数解析器
func NewParameterParser() *ParameterParser {
	return &ParameterParser{}
}

// ParseRequest 解析请求信息，提取所有参数
func (p *ParameterParser) ParseRequest(reqInfo *RequestInfo) []ParameterInfo {
	var parameters []ParameterInfo

	// 解析URL参数
	urlParams := p.parseURLParameters(reqInfo.URL)
	parameters = append(parameters, urlParams...)

	// 解析POST数据
	if reqInfo.Method == "POST" || reqInfo.Method == "PUT" || reqInfo.Method == "PATCH" {
		postParams := p.parsePostData(reqInfo.PostData)
		parameters = append(parameters, postParams...)

		// 解析JSON数据
		jsonParams := p.parseJSONData(reqInfo.JSONData)
		parameters = append(parameters, jsonParams...)
	}

	return parameters
}

// parseURLParameters 解析URL参数
func (p *ParameterParser) parseURLParameters(targetURL string) []ParameterInfo {
	var parameters []ParameterInfo

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return parameters
	}

	query := parsedURL.Query()
	for name, values := range query {
		for _, value := range values {
			parameters = append(parameters, ParameterInfo{
				Name:     name,
				Value:    value,
				Location: "url",
				Type:     p.detectParameterType(value),
			})
		}
	}

	return parameters
}

// parsePostData 解析POST数据
func (p *ParameterParser) parsePostData(postData string) []ParameterInfo {
	var parameters []ParameterInfo

	if postData == "" {
		return parameters
	}

	// 尝试解析为URL编码格式
	if strings.Contains(postData, "=") && !strings.Contains(postData, "{") {
		values, err := url.ParseQuery(postData)
		if err == nil {
			for name, vals := range values {
				for _, value := range vals {
					parameters = append(parameters, ParameterInfo{
						Name:     name,
						Value:    value,
						Location: "post",
						Type:     p.detectParameterType(value),
					})
				}
			}
		}
	}

	return parameters
}

// parseJSONData 解析JSON数据
func (p *ParameterParser) parseJSONData(jsonData string) []ParameterInfo {
	var parameters []ParameterInfo

	if jsonData == "" {
		return parameters
	}

	var jsonObj map[string]interface{}
	if err := json.Unmarshal([]byte(jsonData), &jsonObj); err != nil {
		return parameters
	}

	parameters = p.extractJSONParameters(jsonObj, "")
	return parameters
}

// extractJSONParameters 递归提取JSON参数
func (p *ParameterParser) extractJSONParameters(obj interface{}, prefix string) []ParameterInfo {
	var parameters []ParameterInfo

	switch v := obj.(type) {
	case map[string]interface{}:
		for key, value := range v {
			fullKey := key
			if prefix != "" {
				fullKey = prefix + "." + key
			}

			switch val := value.(type) {
			case string:
				parameters = append(parameters, ParameterInfo{
					Name:     fullKey,
					Value:    val,
					Location: "json",
					Type:     "string",
				})
			case float64:
				parameters = append(parameters, ParameterInfo{
					Name:     fullKey,
					Value:    p.formatNumber(val),
					Location: "json",
					Type:     "number",
				})
			case bool:
				parameters = append(parameters, ParameterInfo{
					Name:     fullKey,
					Value:    p.formatBoolean(val),
					Location: "json",
					Type:     "boolean",
				})
			case []interface{}:
				// 处理数组
				for i, item := range val {
					arrayKey := fullKey + "[" + p.formatNumber(float64(i)) + "]"
					subParams := p.extractJSONParameters(item, arrayKey)
					parameters = append(parameters, subParams...)
				}
			case map[string]interface{}:
				// 递归处理嵌套对象
				subParams := p.extractJSONParameters(val, fullKey)
				parameters = append(parameters, subParams...)
			}
		}
	case []interface{}:
		// 处理根级别的数组
		for i, item := range v {
			arrayKey := prefix + "[" + p.formatNumber(float64(i)) + "]"
			subParams := p.extractJSONParameters(item, arrayKey)
			parameters = append(parameters, subParams...)
		}
	}

	return parameters
}

// detectParameterType 检测参数类型
func (p *ParameterParser) detectParameterType(value string) string {
	value = strings.TrimSpace(value)

	// 检测数字
	if p.isNumber(value) {
		return "number"
	}

	// 检测布尔值
	if value == "true" || value == "false" {
		return "boolean"
	}

	// 检测数组（简单检测）
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		return "array"
	}

	// 检测对象（简单检测）
	if strings.HasPrefix(value, "{") && strings.HasSuffix(value, "}") {
		return "object"
	}

	return "string"
}

// isNumber 检测是否为数字
func (p *ParameterParser) isNumber(s string) bool {
	if s == "" {
		return false
	}

	// 检测整数
	if _, err := p.parseInt(s); err == nil {
		return true
	}

	// 检测浮点数
	if _, err := p.parseFloat(s); err == nil {
		return true
	}

	return false
}

// parseInt 解析整数
func (p *ParameterParser) parseInt(s string) (int64, error) {
	// 简单的整数检测
	if s == "" {
		return 0, fmt.Errorf("empty string")
	}

	// 检查是否只包含数字
	for _, char := range s {
		if char < '0' || char > '9' {
			return 0, fmt.Errorf("not a number")
		}
	}

	// 这里简化处理，实际项目中可能需要更复杂的解析
	return 0, nil
}

// parseFloat 解析浮点数
func (p *ParameterParser) parseFloat(s string) (float64, error) {
	// 简单的浮点数检测
	if s == "" {
		return 0, fmt.Errorf("empty string")
	}

	// 检查是否包含小数点
	if !strings.Contains(s, ".") {
		return 0, fmt.Errorf("not a float")
	}

	// 这里简化处理，实际项目中可能需要更复杂的解析
	return 0, nil
}

// formatNumber 格式化数字
func (p *ParameterParser) formatNumber(n float64) string {
	if n == float64(int64(n)) {
		return p.formatNumber(float64(int64(n)))
	}
	return p.formatNumber(n)
}

// formatBoolean 格式化布尔值
func (p *ParameterParser) formatBoolean(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// FilterSSRFSusceptibleParameters 过滤出可能受SSRF影响的参数
func (p *ParameterParser) FilterSSRFSusceptibleParameters(parameters []ParameterInfo) []ParameterInfo {
	var susceptibleParams []ParameterInfo

	// SSRF相关的参数名关键词
	ssrfKeywords := []string{
		"url", "uri", "link", "href", "src", "path", "file", "include",
		"redirect", "callback", "return", "next", "continue", "goto",
		"target", "destination", "endpoint", "api", "service",
		"proxy", "fetch", "request", "http", "https", "ftp",
		"webhook", "notify", "ping", "check", "test", "validate",
		"import", "export", "load", "save", "download", "upload",
		"image", "img", "picture", "photo", "avatar", "icon",
		"logo", "banner", "background", "css", "js", "script",
		"template", "view", "page", "content", "data", "xml",
		"json", "feed", "rss", "atom", "sitemap", "robots",
	}

	for _, param := range parameters {
		// 检查参数名是否包含SSRF相关关键词
		paramNameLower := strings.ToLower(param.Name)
		for _, keyword := range ssrfKeywords {
			if strings.Contains(paramNameLower, keyword) {
				susceptibleParams = append(susceptibleParams, param)
				break
			}
		}

		// 检查参数值是否看起来像URL
		if p.looksLikeURL(param.Value) {
			susceptibleParams = append(susceptibleParams, param)
		}
	}

	return susceptibleParams
}

// looksLikeURL 检测值是否看起来像URL
func (p *ParameterParser) looksLikeURL(value string) bool {
	value = strings.TrimSpace(value)

	// 基本URL格式检测
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		return true
	}

	if strings.HasPrefix(value, "ftp://") || strings.HasPrefix(value, "file://") {
		return true
	}

	// 检测相对URL
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "./") || strings.HasPrefix(value, "../") {
		return true
	}

	// 检测IP地址格式
	if p.looksLikeIP(value) {
		return true
	}

	// 检测域名格式
	if p.looksLikeDomain(value) {
		return true
	}

	return false
}

// looksLikeIP 检测是否像IP地址
func (p *ParameterParser) looksLikeIP(value string) bool {
	// 简单的IP地址检测
	parts := strings.Split(value, ".")
	if len(parts) == 4 {
		for _, part := range parts {
			if len(part) == 0 || len(part) > 3 {
				return false
			}
			// 这里可以添加更严格的数字检测
		}
		return true
	}
	return false
}

// looksLikeDomain 检测是否像域名
func (p *ParameterParser) looksLikeDomain(value string) bool {
	// 简单的域名检测
	if strings.Contains(value, ".") && !strings.Contains(value, " ") {
		// 检查是否包含常见的域名后缀
		commonSuffixes := []string{".com", ".org", ".net", ".edu", ".gov", ".cn", ".uk", ".de", ".fr", ".jp"}
		for _, suffix := range commonSuffixes {
			if strings.HasSuffix(strings.ToLower(value), suffix) {
				return true
			}
		}
	}
	return false
}
