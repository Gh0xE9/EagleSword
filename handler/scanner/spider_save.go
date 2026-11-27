package scanner

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Gh0xE9/EagleSword/handler/parse"
)

// saveSpiderResults 保存爬虫结果到文件
func saveSpiderResults(outDir string, result *SpiderResult) {
	if result == nil {
		return
	}

	// 创建爬虫结果目录
	spiderDir := filepath.Join(outDir, "spider")
	_ = os.MkdirAll(spiderDir, 0o755)

	// 保存爬取的 URL 列表
	saveToFile(filepath.Join(spiderDir, "crawled_urls.txt"), result.URLs)

	// 保存每个页面的内容
	for url, page := range result.Pages {
		safeName := safeNameFromURL(url, ".html")
		_ = os.WriteFile(filepath.Join(spiderDir, safeName), []byte(page.Body), 0o644)
	}

	// 保存 JS 文件
	jsDir := filepath.Join(spiderDir, "js")
	_ = os.MkdirAll(jsDir, 0o755)
	for jsURL, jsContent := range result.JSFiles {
		safeName := safeNameFromURL(jsURL, ".js")
		formattedJS := parse.FormatJS(jsContent)
		_ = os.WriteFile(filepath.Join(jsDir, safeName), []byte(formattedJS), 0o644)
	}

	// 保存爬虫统计信息
	var stats []string
	stats = append(stats, fmt.Sprintf("Total URLs crawled: %d", len(result.URLs)))
	stats = append(stats, fmt.Sprintf("Total pages: %d", len(result.Pages)))
	stats = append(stats, fmt.Sprintf("Total JS files: %d", len(result.JSFiles)))

	saveToFile(filepath.Join(spiderDir, "spider_stats.txt"), stats)
}
