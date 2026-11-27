package parse

import (
	"net/url"
	"regexp"
	"strings"
)

// ExtractDomains 从文本中提取所有域名
func ExtractDomains(text string) []string {
	if text == "" {
		return nil
	}

	seen := make(map[string]struct{})
	var domains []string

	// 使用更精确的域名正则表达式，包含具体的顶级域名
	// 匹配带协议或不带协议的域名，包含具体的 TLD 列表
	domainRe := regexp.MustCompile(`(?i)['"](([a-zA-Z0-9]+:)?\/\/)?[a-zA-Z0-9\-\.]*?\.(xin|com|cn|net|com\.cn|vip|top|cc|shop|club|wang|xyz|luxe|site|news|pub|fun|online|win|red|loan|ren|mom|net\.cn|org|link|biz|bid|help|tech|date|mobi|so|me|tv|co|vc|pw|video|party|pics|website|store|ltd|ink|trade|live|wiki|space|gift|lol|work|band|info|click|photo|market|tel|social|press|game|kim|org\.cn|games|pro|men|love|studio|rocks|asia|group|science|design|software|engineer|lawyer|fit|beer|tw|我爱你|中国|公司|网络|在线|网址|网店|集团|中文网)(\:\d{1,5})?['"]`)
	matches := domainRe.FindAllStringSubmatch(text, -1)

	for _, match := range matches {
		if len(match) >= 4 {
			// 提取域名部分（去掉引号和协议）
			domainPart := match[1]

			// 移除协议部分
			if strings.Contains(domainPart, "://") {
				parts := strings.Split(domainPart, "://")
				if len(parts) >= 2 {
					domainPart = parts[1]
				}
			}

			// 移除端口部分
			if strings.Contains(domainPart, ":") {
				domainPart = strings.Split(domainPart, ":")[0]
			}

			domain := strings.ToLower(strings.TrimSpace(domainPart))

			// 基本验证
			if len(domain) < 3 || len(domain) > 255 {
				continue
			}

			// 不能以点开头或结尾
			if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
				continue
			}

			// 不能包含连续的点
			if strings.Contains(domain, "..") {
				continue
			}

			// 必须包含至少一个点
			if !strings.Contains(domain, ".") {
				continue
			}

			// 排除一些常见的无效域名
			if isInvalidDomain(domain) {
				continue
			}

			if _, exists := seen[domain]; !exists {
				seen[domain] = struct{}{}
				domains = append(domains, domain)
			}
		}
	}

	return domains
}

// isInvalidDomain 检查是否是无效域名
func isInvalidDomain(domain string) bool {
	// 排除一些常见的无效域名
	invalidDomains := []string{
		"localhost", "127.0.0.1", "0.0.0.0",
		"example.com", "test.com", "demo.com",
		"local", "internal", "private",
	}

	for _, invalid := range invalidDomains {
		if domain == invalid {
			return true
		}
	}

	// 排除看起来像 CSS 属性或 JS 变量的短域名
	if len(domain) < 6 {
		return true
	}

	// 排除包含常见编程关键词的域名
	programmingKeywords := []string{
		"color", "opacity", "width", "height", "size", "scale", "rotation",
		"position", "offset", "anchor", "start", "end", "point", "length",
		"transform", "property", "group", "data", "props", "mprops",
		"setgroupproperty", "dataprops", "strokewidth", "skew", "skewaxis",
	}

	for _, keyword := range programmingKeywords {
		if strings.Contains(domain, keyword) {
			return true
		}
	}

	return false
}

// ExtractDomainsFromURLs 从 URL 列表中提取域名
func ExtractDomainsFromURLs(urls []string) []string {
	seen := make(map[string]struct{})
	var domains []string

	for _, u := range urls {
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}

		domain := strings.ToLower(parsed.Hostname())
		if domain != "" && !isInvalidDomain(domain) {
			if _, exists := seen[domain]; !exists {
				seen[domain] = struct{}{}
				domains = append(domains, domain)
			}
		}
	}

	return domains
}
