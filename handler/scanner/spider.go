package scanner

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Gh0xE9/EagleSword/config"
	"github.com/Gh0xE9/EagleSword/handler/parse"
)

// SpiderResult 爬虫结果
type SpiderResult struct {
	URLs    []string
	Pages   map[string]*HTTPResult
	JSFiles map[string]string
	AllData *parse.ExtractResult
}

// Spider 站点爬虫
func Spider(baseURL string, cookies string, headers map[string]string, proxyURL string) (*SpiderResult, error) {
	fmt.Println(config.ColorCyan("[SPIDER]"), "开始站点爬虫...")

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("URL 解析失败: %w", err)
	}

	baseHost := parsed.Hostname()
	baseScheme := parsed.Scheme

	// 存储已访问的 URL
	visited := make(map[string]bool)
	toVisit := []string{baseURL}

	// 存储结果
	result := &SpiderResult{
		URLs:    []string{},
		Pages:   make(map[string]*HTTPResult),
		JSFiles: make(map[string]string),
		AllData: &parse.ExtractResult{},
	}

	// 并发控制
	var mu sync.Mutex
	var wg sync.WaitGroup
	maxWorkers := 5
	semaphore := make(chan struct{}, maxWorkers)

	for len(toVisit) > 0 {
		// 获取当前批次的 URL
		currentBatch := toVisit
		toVisit = []string{}

		for _, targetURL := range currentBatch {
			if visited[targetURL] {
				continue
			}

			// 检查是否属于同一域名
			targetParsed, err := url.Parse(targetURL)
			if err != nil {
				continue
			}

			if targetParsed.Hostname() != baseHost {
				continue
			}

			visited[targetURL] = true

			wg.Add(1)
			go func(url string) {
				defer wg.Done()
				semaphore <- struct{}{}        // 获取信号量
				defer func() { <-semaphore }() // 释放信号量

				// 获取页面内容
				res, err := WebFetch(url, cookies, headers, proxyURL)
				if err != nil {
					fmt.Fprintf(os.Stderr, "%s 访问失败: %s - %v\n", config.ColorRed("[SPIDER]"), url, err)
					return
				}

				mu.Lock()
				result.Pages[url] = &res
				result.URLs = append(result.URLs, url)
				mu.Unlock()

				fmt.Printf("%s %s status=%d length=%d\n", config.ColorCyan("[SPIDER]"), url, res.Status, len(res.Body))

				// 提取页面中的链接
				newURLs := extractLinksFromHTML(url, res.Body, baseScheme, baseHost)

				mu.Lock()
				for _, newURL := range newURLs {
					if !visited[newURL] {
						// 检查是否已经在待访问列表中
						found := false
						for _, existingURL := range toVisit {
							if existingURL == newURL {
								found = true
								break
							}
						}
						if !found {
							toVisit = append(toVisit, newURL)
						}
					}
				}
				mu.Unlock()

				// 提取 JS 文件
				jsURLs, err := parse.ExtractJSURLs(url, res.Body)
				if err == nil {
					for _, jsURL := range jsURLs {
						if !visited[jsURL] {
							// 获取 JS 内容
							if jsBytes, _, _, err := FetchBytes(jsURL, cookies, headers, proxyURL); err == nil {
								mu.Lock()
								result.JSFiles[jsURL] = string(jsBytes)
								mu.Unlock()
							}
						}
					}
				}

			}(targetURL)
		}

		wg.Wait()

		// 限制爬取深度，避免无限循环
		if len(result.URLs) > 100 {
			fmt.Println(config.ColorYellow("[SPIDER]"), "达到最大爬取数量限制 (100)")
			break
		}

		// 添加延迟，避免过于频繁的请求
		time.Sleep(100 * time.Millisecond)
	}

	// 合并所有数据
	fmt.Println(config.ColorCyan("[SPIDER]"), "合并爬虫数据...")
	for pageURL, page := range result.Pages {
		pageData := parse.ExtractAllData(page.Body)
		// 为页面内容也提取 SECRET 信息
		pageData.SecretFindings = parse.ExtractSecretFindings(pageURL, page.Body)
		pageData.PathFindings = parse.ExtractPathsWithFile(pageURL, page.Body)
		result.AllData = mergeExtractResults(result.AllData, pageData)
	}

	for jsURL, jsContent := range result.JSFiles {
		jsData := parse.ExtractAllData(jsContent)
		jsData.SecretFindings = parse.ExtractSecretFindings(jsURL, jsContent)
		jsData.PathFindings = parse.ExtractPathsWithFile(jsURL, jsContent)
		result.AllData = mergeExtractResults(result.AllData, jsData)
	}

	fmt.Printf("%s 爬虫完成，发现 %d 个页面，%d 个 JS 文件\n",
		config.ColorCyan("[SPIDER]"), len(result.Pages), len(result.JSFiles))

	return result, nil
}

// extractLinksFromHTML 从 HTML 中提取链接
func extractLinksFromHTML(baseURL, htmlContent, baseScheme, baseHost string) []string {
	var links []string
	seen := make(map[string]bool)

	// 提取 href 属性
	hrefRe := regexp.MustCompile(`href\s*=\s*["']([^"']+)["']`)
	hrefMatches := hrefRe.FindAllStringSubmatch(htmlContent, -1)

	for _, match := range hrefMatches {
		if len(match) > 1 {
			link := match[1]
			fullURL := resolveURL(baseURL, link, baseScheme, baseHost)
			if fullURL != "" && !seen[fullURL] {
				links = append(links, fullURL)
				seen[fullURL] = true
			}
		}
	}

	// 提取 src 属性
	srcRe := regexp.MustCompile(`src\s*=\s*["']([^"']+)["']`)
	srcMatches := srcRe.FindAllStringSubmatch(htmlContent, -1)

	for _, match := range srcMatches {
		if len(match) > 1 {
			link := match[1]
			fullURL := resolveURL(baseURL, link, baseScheme, baseHost)
			if fullURL != "" && !seen[fullURL] {
				links = append(links, fullURL)
				seen[fullURL] = true
			}
		}
	}

	// 提取 action 属性
	actionRe := regexp.MustCompile(`action\s*=\s*["']([^"']+)["']`)
	actionMatches := actionRe.FindAllStringSubmatch(htmlContent, -1)

	for _, match := range actionMatches {
		if len(match) > 1 {
			link := match[1]
			fullURL := resolveURL(baseURL, link, baseScheme, baseHost)
			if fullURL != "" && !seen[fullURL] {
				links = append(links, fullURL)
				seen[fullURL] = true
			}
		}
	}

	return links
}

// resolveURL 解析相对 URL 为绝对 URL
func resolveURL(baseURL, relativeURL, baseScheme, baseHost string) string {
	// 如果是绝对 URL，直接返回
	if strings.HasPrefix(relativeURL, "http://") || strings.HasPrefix(relativeURL, "https://") {
		return relativeURL
	}

	// 如果是 javascript: 或其他协议，跳过
	if strings.Contains(relativeURL, ":") && !strings.HasPrefix(relativeURL, "/") {
		return ""
	}

	// 解析基础 URL
	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}

	// 解析相对 URL
	relative, err := url.Parse(relativeURL)
	if err != nil {
		return ""
	}

	// 合并 URL
	resolved := base.ResolveReference(relative)

	// 检查是否属于同一域名
	if resolved.Hostname() != baseHost {
		return ""
	}

	// 标准化 URL，移除尾部斜杠（除非是根路径）
	finalURL := resolved.String()
	if strings.HasSuffix(finalURL, "/") && resolved.Path != "/" {
		finalURL = strings.TrimSuffix(finalURL, "/")
	}

	// 过滤掉非页面资源
	path := resolved.Path
	if strings.Contains(path, ".") {
		ext := strings.ToLower(path[strings.LastIndex(path, "."):])
		resourceExts := []string{".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot"}
		for _, resourceExt := range resourceExts {
			if ext == resourceExt {
				return ""
			}
		}
	}

	return finalURL
}
