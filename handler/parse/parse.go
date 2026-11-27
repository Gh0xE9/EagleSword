package parse

import (
	"net/url"
	"regexp"
	"strings"
)

func ExtractJSURLs(base string, html string) ([]string, error) {
	baseURL, _ := url.Parse(base)
	seen := map[string]struct{}{}

	re := regexp.MustCompile(`(?is)<\s*(script|a)[^>]+?(src|href)\s*=\s*["']\s*([^"'>]+)\s*["']`)
	matches := re.FindAllStringSubmatch(html, -1)
	for _, m := range matches {
		if len(m) < 4 {
			continue
		}
		raw := strings.TrimSpace(m[3])
		if raw == "" {
			continue
		}
		lowerPath := strings.ToLower(strings.SplitN(raw, "?", 2)[0])
		if !strings.HasSuffix(lowerPath, ".js") {
			continue
		}

		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		abs := u
		if !u.IsAbs() && baseURL != nil {
			abs = baseURL.ResolveReference(u)
		}
		s := abs.String()
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
	}

	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	return out, nil
}

// ExtractAllURLs 提取页面内所有可能的 URL（script/src、a/href、link/href、img/src 等常见位置）
// 返回绝对化并去重的 URL 列表
func ExtractAllURLs(base string, html string) ([]string, error) {
	baseURL, _ := url.Parse(base)
	seen := map[string]struct{}{}

	re := regexp.MustCompile(`(?is)<\s*(script|a|link|img|source|video|audio)[^>]+?(src|href)\s*=\s*["']\s*([^"'>]+)\s*["']`)
	matches := re.FindAllStringSubmatch(html, -1)
	for _, m := range matches {
		if len(m) < 4 {
			continue
		}
		raw := strings.TrimSpace(m[3])
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		abs := u
		if !u.IsAbs() && baseURL != nil {
			abs = baseURL.ResolveReference(u)
		}
		s := abs.String()
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
	}

	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	return out, nil
}
