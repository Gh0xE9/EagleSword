package scanner

import (
	"fmt"
	htmlpkg "html"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Gh0xE9/EagleSword/config"
	"github.com/Gh0xE9/EagleSword/handler/parse"
	"github.com/Gh0xE9/EagleSword/handler/vuln"
)

// generateHTMLReport 生成 HTML 报告
func generateHTMLReport(outDir, targetURL string, res *HTTPResult, data *parse.ExtractResult, apiResults []parse.APIResult, spiderResult *SpiderResult, directoryResults []DirectoryResult, fingerprintResults []FingerprintResult, corsResult *vuln.CORSCheckResult) {
	// 生成时间戳
	timestamp := time.Now().Format("20060102_150405")

	// 从 URL 提取站点名称
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return
	}
	siteName := parsed.Hostname()

	// 生成报告文件名
	reportName := fmt.Sprintf("eaglesword_%s_%s.html", timestamp, siteName)
	reportPath := filepath.Join(outDir, reportName)

	// 生成 HTML 内容
	htmlContent := generateHTMLContent(targetURL, res, data, apiResults, spiderResult, directoryResults, fingerprintResults, corsResult, timestamp)

	// 保存 HTML 文件
	_ = os.WriteFile(reportPath, []byte(htmlContent), 0o644)

	fmt.Printf("[REPORT]: %s\n", reportPath)
}

// generateHTMLContent 生成 HTML 内容
func generateHTMLContent(targetURL string, res *HTTPResult, data *parse.ExtractResult, apiResults []parse.APIResult, spiderResult *SpiderResult, directoryResults []DirectoryResult, fingerprintResults []FingerprintResult, corsResult *vuln.CORSCheckResult, timestamp string) string {
	// 提取网站标题
	title := extractTitle(res.Body)
	if title == "" {
		title = "EagleSword 扫描报告"
	}

	// 提取网站图标URL
	faviconURL := extractFaviconURL(targetURL, res.Body)
	var faviconLink string
	if faviconURL != "" {
		faviconLink = fmt.Sprintf(`    <link rel="icon" href="%s" type="image/x-icon">`, faviconURL)
	}

	// 生成网站图标HTML
	var siteIconHTML string
	if faviconURL != "" {
		siteIconHTML = fmt.Sprintf(`<img src="%s" alt="网站图标" class="site-icon" onerror="this.style.display='none'">`, faviconURL)
	} else {
		siteIconHTML = `<div class="site-icon-placeholder">🌐</div>`
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s - EagleSword 扫描报告</title>
    %s
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
            font-size: 14px;
        }

        .container {
            max-width: 100%%;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid #ddd;
        }

        .header-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .site-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .site-icon {
            width: 48px;
            height: 48px;
            border-radius: 8px;
            object-fit: cover;
        }

        .site-icon-placeholder {
            width: 48px;
            height: 48px;
            background:#e80030;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            color: white;
        }

        .site-details h1 {
            font-size: 24px;
            font-weight: bold;
            color: #333;
            margin-bottom: 5px;
        }

        .site-url {
            font-size: 14px;
            color: #666;
            text-decoration: none;
        }

        .site-url:hover {
            color:#e80030;
        }


        .eaglesword-brand {
            text-align: right;
        }

        .eaglesword-brand h2 {
            font-size: 20px;
            font-weight: bold;
            color: #e80030;
            margin-bottom: 5px;
        }

        .header-stats {
            margin-top: 20px;
        }

        .section {
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid #ddd;
        }

        .section h2 {
            font-size: 18px;
            font-weight: bold;
            color: #333;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e80030;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }

        .stat-card {
            background: #f8f9fa;
            padding: 15px;
            border: 1px solid #e9ecef;
            text-align: center;
        }

        .stat-number {
            font-size: 24px;
            font-weight: bold;
            color: #e80030;
            display: block;
            margin-bottom: 5px;
        }

        .stat-label {
            font-size: 12px;
            color: #666;
        }

        .data-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }

        .data-card {
            background: #f8f9fa;
            padding: 15px;
            border: 1px solid #e9ecef;
        }

        .data-card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }

        .data-card-actions {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .data-card-title {
            font-size: 14px;
            font-weight: bold;
            color: #333;
        }

        .data-count {
            background: #e80030;
            color: white;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
        }

        .data-list {
            max-height: 200px;
            overflow-y: auto;
        }

        .data-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0;
            border-bottom: 1px solid #e9ecef;
            font-family: monospace;
            font-size: 12px;
        }

        .data-item:last-child {
            border-bottom: none;
        }

        .data-text {
            color: #333;
            word-break: break-all;
            flex: 1;
            margin-right: 10px;
        }

        .copy-btn {
            background: #28a745;
            color: white;
            border: none;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            cursor: pointer;
            flex-shrink: 0;
        }

        .copy-btn:hover {
            background: #218838;
        }

        .copy-all-btn {
            background: #ffc107;
            color: #333;
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            font-size: 12px;
            cursor: pointer;
        }

        .copy-all-btn:hover {
            background: #e0a800;
        }

        .table-container {
            overflow-x: auto;
            border: 1px solid #ddd;
        }

        .data-table {
            width: 100%%;
            border-collapse: collapse;
            background: white;
            table-layout: fixed;
        }

        .data-table th:nth-child(1) { width: 20%%; }
        .data-table th:nth-child(2) { width: 8%%; }
        .data-table th:nth-child(3) { width: 8%%; }
        .data-table th:nth-child(4) { width: 8%%; }
        .data-table th:nth-child(5) { width: 15%%; }
        .data-table th:nth-child(6) { width: 41%%; }

        .data-table th {
            background: #e80030;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: bold;
            font-size: 12px;
        }

        .data-table td {
            padding: 12px;
            border-bottom: 1px solid #ddd;
            font-size: 12px;
        }

        .data-table tr:hover {
            background: #f8f9fa;
        }

        .data-table tr:last-child td {
            border-bottom: none;
        }

        .status-badge {
            padding: 2px 6px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: bold;
            text-align: center;
            min-width: 50px;
            display: inline-block;
        }

        .status-200 { background: #28a745; color: white; }
        .status-300 { background: #ffc107; color: #333; }
        .status-400 { background: #dc3545; color: white; }
        .status-500 { background: #6f42c1; color: white; }

        .method-badge {
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
        }

        .method-get { background: #28a745; color: white; }
        .method-post { background: #dc3545; color: white; }
        .method-put { background: #fd7e14; color: white; }
        .method-delete { background: #6f42c1; color: white; }
        .method-options { background: #20c997; color: white; }
        .method-patch { background: #e83e8c; color: white; }
        .method-head { background: #6c757d; color: white; }
        .method-other { background: #495057; color: white; }

        .response-content {
            max-width: 400px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            font-family: monospace;
            font-size: 11px;
            color: #666;
        }

        .footer {
            background: white;
            padding: 20px;
            text-align: center;
            border: 1px solid #ddd;
            margin-top: 20px;
        }

        .sort-btn {
            background: none;
            border: none;
            color: white;
            cursor: pointer;
            font-size: 12px;
            margin-left: 5px;
            padding: 2px 4px;
            border-radius: 3px;
        }

        .sort-btn:hover {
            background: rgba(255, 255, 255, 0.2);
        }

        .sort-btn.active {
            background: rgba(255, 255, 255, 0.3);
        }

        .filter-buttons {
            display: flex;
            flex-wrap: wrap;
            gap: 2px;
            margin-top: 5px;
        }

        .filter-btn {
            background: #4a5568;
            border: 1px solid #718096;
            color: white;
            cursor: pointer;
            font-size: 10px;
            padding: 2px 6px;
            border-radius: 3px;
            transition: all 0.2s ease;
        }

        .filter-btn:hover {
            background: #2d3748;
            border-color: #a0aec0;
        }

        .filter-btn.active {
            background: #3182ce;
            border-color: #3182ce;
            color: white;
        }

        /* 大纲导航样式 */
        .outline-nav {
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }

        .outline-nav h3 {
            margin: 0 0 15px 0;
            color: #495057;
            font-size: 18px;
            font-weight: 600;
        }

        .outline-list {
            list-style: none;
            padding: 0;
            margin: 0;
        }

        .outline-list li {
            margin: 8px 0;
        }

        .outline-list a {
            color: #6c757d;
            text-decoration: none;
            padding: 8px 12px;
            border-radius: 4px;
            display: block;
            transition: all 0.2s ease;
        }

        .outline-list a:hover {
            background: #e9ecef;
            color: #495057;
        }

        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }

            .header-content {
                flex-direction: column;
                gap: 15px;
                text-align: center;
            }

            .stats-grid,
            .data-grid {
                grid-template-columns: 1fr;
            }

            .data-table {
                font-size: 11px;
            }

            .data-table th,
            .data-table td {
                padding: 8px;
            }
        }
    </style>
    <script>
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(function() {
                alert('已复制到剪贴板');
            }, function(err) {
                console.error('复制失败: ', err);
            });
        }
        
        function sortTable(tableId, columnIndex, sortOrder) {
            const table = document.getElementById(tableId);
            if (!table) return;
            
            const tbody = table.querySelector('tbody');
            if (!tbody) return;
            
            const rows = Array.from(tbody.querySelectorAll('tr'));
            
            // 移除所有排序按钮的active状态
            const allSortBtns = table.querySelectorAll('.sort-btn');
            allSortBtns.forEach(btn => btn.classList.remove('active'));
            
            // 设置当前排序按钮为active
            const currentSortBtn = event.target;
            currentSortBtn.classList.add('active');
            
            rows.sort(function(a, b) {
                const aValue = parseInt(a.cells[columnIndex].textContent.trim()) || 0;
                const bValue = parseInt(b.cells[columnIndex].textContent.trim()) || 0;
                
                if (sortOrder === 'asc') {
                    return aValue - bValue;
                } else {
                    return bValue - aValue;
                }
            });
            
            // 重新插入排序后的行
            rows.forEach(row => tbody.appendChild(row));
        }
        
        function filterMethod(tableId, method) {
            const table = document.getElementById(tableId);
            if (!table) return;
            
            const tbody = table.querySelector('tbody');
            if (!tbody) return;
            
            const rows = tbody.querySelectorAll('tr');
            
            // 移除所有筛选按钮的active状态
            const filterButtons = table.querySelectorAll('.filter-btn');
            filterButtons.forEach(btn => btn.classList.remove('active'));
            
            // 设置当前筛选按钮为active
            event.target.classList.add('active');
            
            rows.forEach(function(row) {
                const methodCell = row.cells[1]; // Method列是第2列（索引1）
                if (!methodCell) return;
                
                const methodText = methodCell.textContent.trim();
                
                if (method === 'all' || methodText === method) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        }
        
        function copyAllFromTable(tableId) {
            const table = document.getElementById(tableId);
            if (!table) return;
            
            let allText = '';
            const rows = table.querySelectorAll('tbody tr');
            
            if (tableId === 'secret-table') {
                // 敏感信息只复制类型字段（第一列）
                rows.forEach(function(row) {
                    const typeCell = row.cells[0];
                    if (typeCell) {
                        allText += typeCell.textContent.trim() + '\n';
                    }
                });
            } else if (tableId === 'api-table') {
                // API端点只复制路径字段（第一列）
                rows.forEach(function(row) {
                    const pathCell = row.cells[0];
                    if (pathCell) {
                        allText += pathCell.textContent.trim() + '\n';
                    }
                });
            } else if (tableId === 'directory-table') {
                // 目录探测只复制路径字段（第一列）
                rows.forEach(function(row) {
                    const pathCell = row.cells[0];
                    if (pathCell) {
                        allText += pathCell.textContent.trim() + '\n';
                    }
                });
            } else if (tableId === 'cors-table') {
                // CORS检测只复制URL字段（第一列）
                rows.forEach(function(row) {
                    const urlCell = row.cells[0];
                    if (urlCell) {
                        allText += urlCell.textContent.trim() + '\n';
                    }
                });
            } else {
                // 其他表格复制所有内容
                rows.forEach(function(row) {
                    const cells = row.querySelectorAll('td');
                    const rowText = Array.from(cells).map(cell => cell.textContent.trim()).join('\t');
                    allText += rowText + '\n';
                });
            }
            
            navigator.clipboard.writeText(allText.trim()).then(function() {
                alert('已复制全部内容到剪贴板');
            }, function(err) {
                console.error('复制失败: ', err);
            });
        }
    </script>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="header-content">
                <div class="site-info">
                    %s
                    <div class="site-details">
                        <h1>%s</h1>
                        <a href="%s" class="site-url" target="_blank">%s</a>
                    </div>
                </div>
                <div class="eaglesword-brand">
                    <h2>EagleSword</h2>
                    <p>%s</p>
                </div>
            </div>
            <div class="header-stats">
                <div class="stats-grid">
                    <div class="stat-card">
                        <span class="stat-number">`+fmt.Sprintf("%d", res.Status)+`</span>
                        <span class="stat-label">HTTP Code</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-number">`+fmt.Sprintf("%d", len(res.Body))+`</span>
                        <span class="stat-label">Response Length</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-number">`+fmt.Sprintf("%d", getDataLength(data, func(d *parse.ExtractResult) int { return len(d.URL) }))+`</span>
                        <span class="stat-label">URL Count</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-number">`+fmt.Sprintf("%d", getDataLength(data, func(d *parse.ExtractResult) int { return len(d.Domain) }))+`</span>
                        <span class="stat-label">Domain Count</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-number">`+fmt.Sprintf("%d", getDataLength(data, func(d *parse.ExtractResult) int { return len(d.IP) }))+`</span>
                        <span class="stat-label">IP Count</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-number">`+fmt.Sprintf("%d", getDataLength(data, func(d *parse.ExtractResult) int { return len(d.Mail) }))+`</span>
                        <span class="stat-label">Email Count</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-number">`+fmt.Sprintf("%d", getDataLength(data, func(d *parse.ExtractResult) int { return len(d.Mobile) }))+`</span>
                        <span class="stat-label">Mobile Count</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-number">`+fmt.Sprintf("%d", getDataLength(data, func(d *parse.ExtractResult) int { return len(d.Path) }))+`</span>
                        <span class="stat-label">Path Count</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-number">`+fmt.Sprintf("%d", getDataLength(data, func(d *parse.ExtractResult) int { return len(d.SecretFindings) }))+`</span>
                        <span class="stat-label">Secret Count</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-number">`+fmt.Sprintf("%d", len(apiResults))+`</span>
                        <span class="stat-label">API Count</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-number">`+fmt.Sprintf("%d", len(directoryResults))+`</span>
                        <span class="stat-label">Directory Count</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-number">`+fmt.Sprintf("%d", getSpiderLength(spiderResult))+`</span>
                        <span class="stat-label">Spider Count</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-number">`+fmt.Sprintf("%d", len(fingerprintResults))+`</span>
                        <span class="stat-label">Fingerprint Count</span>
                    </div>
                </div>
            </div>
        </header>

        <main>`, title, faviconLink, siteIconHTML, title, targetURL, timestamp, config.VERSION)

	// 添加大纲导航
	html += `
        <!-- 大纲导航 -->
        <nav class="outline-nav">
            <h3>Report Outline</h3>
            <ul class="outline-list">`

	// 根据数据动态生成大纲
	if spiderResult != nil {
		html += `<li><a href="#spider-section">Spider Result</a></li>`
	}
	if data != nil && (len(data.URL) > 0 || len(data.Domain) > 0 || len(data.IP) > 0 || len(data.Mail) > 0 || len(data.Mobile) > 0 || len(data.Path) > 0) {
		html += `<li><a href="#data-extraction">Data Extraction Result</a></li>`
	}
	if data != nil && len(data.SecretFindings) > 0 {
		html += `<li><a href="#secret-findings">Secret Finding</a></li>`
	}
	if len(apiResults) > 0 {
		html += `<li><a href="#api-results">API Test Result</a></li>`
	}
	if len(directoryResults) > 0 {
		html += `<li><a href="#directory-results">Directory Test Result</a></li>`
	}
	if len(fingerprintResults) > 0 {
		html += `<li><a href="#fingerprint-results">Fingerprint Test Result</a></li>`
	}
	if corsResult != nil {
		html += `<li><a href="#cors-results">CORS Vulnerability Test Result</a></li>`
	}

	html += `
            </ul>
        </nav>`

	// 添加爬虫结果
	if spiderResult != nil && len(spiderResult.URLs) > 0 {
		html += `
            <div class="section" id="spider-section">
                <h2>Spider Result</h2>
                <div class="stats-grid">
                    <div class="stat-card">
                        <span class="stat-number">` + fmt.Sprintf("%d", len(spiderResult.URLs)) + `</span>
                        <span class="stat-label">Crawled Page</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-number">` + fmt.Sprintf("%d", len(spiderResult.JSFiles)) + `</span>
                        <span class="stat-label">JS File</span>
                    </div>
                </div>
                <div class="data-card">
                    <div class="data-card-header">
                        <h3 class="data-card-title">Crawled URL List</h3>
                        <button class="copy-all-btn" onclick="copyAllFromList('spider-urls')">Copy All</button>
                    </div>
                    <div class="data-list" id="spider-urls">`
		for _, url := range spiderResult.URLs {
			html += `<div class="data-item">
                        <span class="data-text"><a href="` + htmlpkg.EscapeString(url) + `" target="_blank">` + htmlpkg.EscapeString(url) + `</a></span>
                        <button class="copy-btn" onclick="copyToClipboard('` + htmlpkg.EscapeString(url) + `')">Copy</button>
                    </div>`
		}
		html += `</div></div></div>`
	} else {
		// 即使没有爬虫结果，也显示目标URL
		html += `
            <div class="section" id="spider-section">
                <h2>Spider Result</h2>
                <div class="stats-grid">
                    <div class="stat-card">
                        <span class="stat-number">1</span>
                        <span class="stat-label">Target Page</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-number">0</span>
                        <span class="stat-label">JS File</span>
                    </div>
                </div>
                <div class="data-card">
                    <div class="data-card-header">
                        <h3 class="data-card-title">Target URL</h3>
                        <button class="copy-all-btn" onclick="copyAllFromList('spider-urls')">Copy All</button>
                    </div>
                    <div class="data-list" id="spider-urls">
                        <div class="data-item">
                            <span class="data-text"><a href="` + htmlpkg.EscapeString(targetURL) + `" target="_blank">` + htmlpkg.EscapeString(targetURL) + `</a></span>
                            <button class="copy-btn" onclick="copyToClipboard('` + htmlpkg.EscapeString(targetURL) + `')">Copy</button>
                        </div>
                    </div>
                </div>
            </div>`
	}

	// 添加数据提取结果
	if data != nil {
		html += `
            <div class="section" id="data-extraction">
                <h2>Data Extraction Result</h2>
                <div class="data-grid">`

		// URL地址
		if len(data.URL) > 0 {
			html += `<div class="data-card">
                    <div class="data-card-header">
                        <h3 class="data-card-title">URL Address</h3>
                        <div class="data-card-actions">
                            <span class="data-count">` + fmt.Sprintf("%d", len(data.URL)) + `</span>
                            <button class="copy-all-btn" onclick="copyAllFromList('url-list')">Copy All</button>
                        </div>
                    </div>
                    <div class="data-list" id="url-list">`
			for _, url := range data.URL {
				html += `<div class="data-item">
                        <span class="data-text">` + htmlpkg.EscapeString(url) + `</span>
                        <button class="copy-btn" onclick="copyToClipboard('` + htmlpkg.EscapeString(url) + `')">Copy</button>
                    </div>`
			}
			html += `</div></div>`
		}

		// 域名
		if len(data.Domain) > 0 {
			html += `<div class="data-card">
                    <div class="data-card-header">
                        <h3 class="data-card-title">Domain</h3>
                        <div class="data-card-actions">
                            <span class="data-count">` + fmt.Sprintf("%d", len(data.Domain)) + `</span>
                            <button class="copy-all-btn" onclick="copyAllFromList('domain-list')">Copy All</button>
                        </div>
                    </div>
                    <div class="data-list" id="domain-list">`
			for _, domain := range data.Domain {
				html += `<div class="data-item">
                        <span class="data-text">` + htmlpkg.EscapeString(domain) + `</span>
                        <button class="copy-btn" onclick="copyToClipboard('` + htmlpkg.EscapeString(domain) + `')">Copy</button>
                    </div>`
			}
			html += `</div></div>`
		}

		// IP地址
		if len(data.IP) > 0 {
			html += `<div class="data-card">
                    <div class="data-card-header">
                        <h3 class="data-card-title">IP Address</h3>
                        <div class="data-card-actions">
                            <span class="data-count">` + fmt.Sprintf("%d", len(data.IP)) + `</span>
                            <button class="copy-all-btn" onclick="copyAllFromList('ip-list')">Copy All</button>
                        </div>
                    </div>
                    <div class="data-list" id="ip-list">`
			for _, ip := range data.IP {
				html += `<div class="data-item">
                        <span class="data-text">` + htmlpkg.EscapeString(ip) + `</span>
                        <button class="copy-btn" onclick="copyToClipboard('` + htmlpkg.EscapeString(ip) + `')">Copy</button>
                    </div>`
			}
			html += `</div></div>`
		}

		// 邮箱
		if len(data.Mail) > 0 {
			html += `<div class="data-card">
                    <div class="data-card-header">
                        <h3 class="data-card-title">Email Address</h3>
                        <div class="data-card-actions">
                            <span class="data-count">` + fmt.Sprintf("%d", len(data.Mail)) + `</span>
                            <button class="copy-all-btn" onclick="copyAllFromList('mail-list')">Copy All</button>
                        </div>
                    </div>
                    <div class="data-list" id="mail-list">`
			for _, mail := range data.Mail {
				html += `<div class="data-item">
                        <span class="data-text">` + htmlpkg.EscapeString(mail) + `</span>
                        <button class="copy-btn" onclick="copyToClipboard('` + htmlpkg.EscapeString(mail) + `')">Copy</button>
                    </div>`
			}
			html += `</div></div>`
		}

		// 手机号
		if len(data.Mobile) > 0 {
			html += `<div class="data-card">
                    <div class="data-card-header">
                        <h3 class="data-card-title">Mobile Number</h3>
                        <div class="data-card-actions">
                            <span class="data-count">` + fmt.Sprintf("%d", len(data.Mobile)) + `</span>
                            <button class="copy-all-btn" onclick="copyAllFromList('mobile-list')">Copy All</button>
                        </div>
                    </div>
                    <div class="data-list" id="mobile-list">`
			for _, mobile := range data.Mobile {
				html += `<div class="data-item">
                        <span class="data-text">` + htmlpkg.EscapeString(mobile) + `</span>
                        <button class="copy-btn" onclick="copyToClipboard('` + htmlpkg.EscapeString(mobile) + `')">Copy</button>
                    </div>`
			}
			html += `</div></div>`
		}

		// 路径
		if len(data.Path) > 0 {
			html += `<div class="data-card">
                    <div class="data-card-header">
                        <h3 class="data-card-title">Path</h3>
                        <div class="data-card-actions">
                            <span class="data-count">` + fmt.Sprintf("%d", len(data.Path)) + `</span>
                            <button class="copy-all-btn" onclick="copyAllFromList('path-list')">Copy All</button>
                        </div>
                    </div>
                    <div class="data-list" id="path-list">`
			for _, path := range data.Path {
				html += `<div class="data-item">
                        <span class="data-text">` + htmlpkg.EscapeString(path) + `</span>
                        <button class="copy-btn" onclick="copyToClipboard('` + htmlpkg.EscapeString(path) + `')">Copy</button>
                    </div>`
			}
			html += `</div></div>`
		}

		html += `</div></div>`

		// 添加敏感信息
		if len(data.SecretFindings) > 0 {
			html += `
            <div class="section" id="secret-findings">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                    <h2 style="margin: 0;">Sensitive Information Finding</h2>
                    <button class="copy-all-btn" onclick="copyAllFromTable('secret-table')">Copy All</button>
                </div>
                <div class="table-container">
                    <table class="data-table" id="secret-table">
                        <thead>
                            <tr>
                                <th>Type</th>
                                <th>File</th>
                                <th>Line Number</th>
                                <th>Content</th>
                            </tr>
                        </thead>
                        <tbody>`
			for _, secret := range data.SecretFindings {
				html += `<tr>
                            <td><span class="status-badge status-200">` + htmlpkg.EscapeString(secret.Field) + `</span></td>
                            <td>` + htmlpkg.EscapeString(secret.File) + `</td>
                            <td>` + fmt.Sprintf("%d", secret.Line) + `</td>
                            <td>` + htmlpkg.EscapeString(secret.Field) + `</td>
                        </tr>`
			}
			html += `</tbody></table></div></div>`
		}
	}

	// 添加API测试结果
	if len(apiResults) > 0 {
		html += `
            <div class="section" id="api-results">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                    <h2 style="margin: 0;">API Endpoint Test Result</h2>
                    <button class="copy-all-btn" onclick="copyAllFromTable('api-table')">Copy All</button>
                </div>
                <div class="table-container">
                    <table class="data-table" id="api-table">
                        <thead>
                            <tr>
                                <th>URL</th>
                                <th>Method
                                    <div class="filter-buttons">
                                        <button class="filter-btn active" onclick="filterMethod('api-table', 'all')" title="显示所有">All</button>
                                        <button class="filter-btn" onclick="filterMethod('api-table', 'GET')" title="只显示GET请求">GET</button>
                                        <button class="filter-btn" onclick="filterMethod('api-table', 'POST')" title="只显示POST请求">POST</button>
                                        <button class="filter-btn" onclick="filterMethod('api-table', 'PUT')" title="只显示PUT请求">PUT</button>
                                        <button class="filter-btn" onclick="filterMethod('api-table', 'DELETE')" title="只显示DELETE请求">DELETE</button>
                                        <button class="filter-btn" onclick="filterMethod('api-table', 'OPTIONS')" title="只显示OPTIONS请求">OPTIONS</button>
                                        <button class="filter-btn" onclick="filterMethod('api-table', 'PATCH')" title="只显示PATCH请求">PATCH</button>
                                        <button class="filter-btn" onclick="filterMethod('api-table', 'HEAD')" title="只显示HEAD请求">HEAD</button>
                                    </div>
                                </th>
                                <th>Status Code</th>
                                <th>Response Length
                                    <button class="sort-btn" onclick="sortTable('api-table', 3, 'asc')" title="从小到大排序">↑</button>
                                    <button class="sort-btn" onclick="sortTable('api-table', 3, 'desc')" title="从大到小排序">↓</button>
                                </th>
                                <th>Title</th>   
                                <th>Response Content</th>
                            </tr>
                        </thead>
                        <tbody>`
		for _, result := range apiResults {
			// 直接使用完整的URL，不提取路径
			fullURL := result.URL
			statusClass := ""
			if result.Status >= 200 && result.Status < 300 {
				statusClass = "status-200"
			} else if result.Status >= 300 && result.Status < 400 {
				statusClass = "status-300"
			} else if result.Status >= 400 && result.Status < 500 {
				statusClass = "status-400"
			} else if result.Status >= 500 {
				statusClass = "status-500"
			}

			methodClass := ""
			if result.Method == "GET" {
				methodClass = "method-get"
			} else if result.Method == "POST" {
				methodClass = "method-post"
			} else if result.Method == "PUT" {
				methodClass = "method-put"
			} else if result.Method == "DELETE" {
				methodClass = "method-delete"
			} else if result.Method == "OPTIONS" {
				methodClass = "method-options"
			} else if result.Method == "PATCH" {
				methodClass = "method-patch"
			} else if result.Method == "HEAD" {
				methodClass = "method-head"
			} else {
				methodClass = "method-other"
			}

			html += `<tr>
                        <td><a href="` + htmlpkg.EscapeString(fullURL) + `" target="_blank">` + htmlpkg.EscapeString(fullURL) + `</a></td>
                        <td><span class="method-badge ` + methodClass + `">` + result.Method + `</span></td>
                        <td><span class="status-badge ` + statusClass + `">` + fmt.Sprintf("%d", result.Status) + `</span></td>
                        <td>` + fmt.Sprintf("%d", result.Length) + `</td>
                        <td>` + htmlpkg.EscapeString(result.Title) + `</td>
                        <td><span class="response-content">` + htmlpkg.EscapeString(result.Response) + `</span></td>
                    </tr>`
		}
		html += `</tbody></table></div></div>`
	}

	// 添加目录探测结果
	if len(directoryResults) > 0 {
		html += `
            <div class="section" id="directory-results">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                    <h2 style="margin: 0;">Directory Test Result</h2>
                    <button class="copy-all-btn" onclick="copyAllFromTable('directory-table')">Copy All</button>
                </div>
                <div class="table-container">
                    <table class="data-table" id="directory-table">
                        <thead>
                            <tr>
                                <th>URL</th>
                                <th>Status Code</th>
                                <th>Response Length
                                    <button class="sort-btn" onclick="sortTable('directory-table', 2, 'asc')" title="从小到大排序">↑</button>
                                    <button class="sort-btn" onclick="sortTable('directory-table', 2, 'desc')" title="从大到小排序">↓</button>
                                </th>
                                <th>Title</th>
                                <th>Response Content</th>
                            </tr>
                        </thead>
                        <tbody>`
		for _, result := range directoryResults {
			// 直接使用完整的URL，不提取路径
			fullURL := result.URL
			statusClass := ""
			if result.Status == 200 {
				statusClass = "status-200"
			} else if result.Status >= 300 && result.Status < 400 {
				statusClass = "status-300"
			} else if result.Status >= 400 && result.Status < 500 {
				statusClass = "status-400"
			} else if result.Status >= 500 {
				statusClass = "status-500"
			}

			html += `<tr>
                        <td><a href="` + htmlpkg.EscapeString(fullURL) + `" target="_blank">` + htmlpkg.EscapeString(fullURL) + `</a></td>
                        <td><span class="status-badge ` + statusClass + `">` + fmt.Sprintf("%d", result.Status) + `</span></td>
                        <td>` + fmt.Sprintf("%d", result.Length) + `</td>
                        <td>` + htmlpkg.EscapeString(result.Title) + `</td>
                        <td><span class="response-content">` + htmlpkg.EscapeString(result.Response) + `</span></td>
                    </tr>`
		}
		html += `</tbody></table></div></div>`
	}

	// 添加指纹识别结果
	if len(fingerprintResults) > 0 {
		html += `
            <div class="section" id="fingerprint-results">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                    <h2 style="margin: 0;">Fingerprint Test Result</h2>
                    <button class="copy-all-btn" onclick="copyAllFromTable('fingerprint-table')">Copy All</button>
                </div>
                <div class="table-container">
                    <table class="data-table" id="fingerprint-table">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Product</th>
                                <th>Vendor</th>
                                <th>Severity</th>
                            </tr>
                        </thead>
                        <tbody>`
		for _, result := range fingerprintResults {
			severityClass := ""
			switch result.Severity {
			case "critical":
				severityClass = "status-500"
			case "high":
				severityClass = "status-400"
			case "medium":
				severityClass = "status-300"
			case "low", "info":
				severityClass = "status-200"
			default:
				severityClass = "status-200"
			}

			html += `<tr>
                        <td>` + htmlpkg.EscapeString(result.Name) + `</td>
                        <td>` + htmlpkg.EscapeString(result.Product) + `</td>
                        <td>` + htmlpkg.EscapeString(result.Vendor) + `</td>
                        <td><span class="status-badge ` + severityClass + `">` + htmlpkg.EscapeString(result.Severity) + `</span></td>
                    </tr>`
		}
		html += `</tbody></table></div></div>`
	}

	// 添加CORS检测结果
	if corsResult != nil {
		html += `
            <div class="section" id="cors-results">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                    <h2 style="margin: 0;">CORS Vulnerability Test Result</h2>
                    <button class="copy-all-btn" onclick="copyAllFromTable('cors-table')">Copy All</button>
                </div>
                <div class="table-container">
                    <table class="data-table" id="cors-table" style="table-layout: fixed;">
                        <thead>
                            <tr>
                                <th style="width: 25%;">URL</th>
                                <th style="width: 15%;">Test Origin</th>
                                <th style="width: 20%;">Allow-Origin</th>
                                <th style="width: 15%;">Allow-Methods</th>
                                <th style="width: 10%;">Credentials</th>
                                <th style="width: 8%;">Vulnerable</th>
                                <th style="width: 7%;">Reason</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td style="word-break: break-all;"><a href="` + htmlpkg.EscapeString(corsResult.URL) + `" target="_blank">` + htmlpkg.EscapeString(corsResult.URL) + `</a></td>
                                <td>` + htmlpkg.EscapeString(corsResult.Origin) + `</td>
                                <td style="word-break: break-all;">` + htmlpkg.EscapeString(corsResult.AccessControlAllowOrigin) + `</td>
                                <td style="word-break: break-all;">` + htmlpkg.EscapeString(corsResult.AccessControlAllowMethods) + `</td>
                                <td>` + htmlpkg.EscapeString(corsResult.AccessControlAllowCredentials) + `</td>
                                <td><span class="status-badge ` + func() string {
			if corsResult.IsVulnerable {
				return "status-500"
			}
			return "status-200"
		}() + `">` + func() string {
			if corsResult.IsVulnerable {
				return "Yes"
			}
			return "No"
		}() + `</span></td>
                                <td style="word-break: break-word;">` + htmlpkg.EscapeString(corsResult.VulnerabilityReason) + `</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>`
	}

	html += fmt.Sprintf(`
        </main>

        <footer class="footer">
            <p>Generated by EagleSword | Scan time: %s</p>
        </footer>
    </div>
</body>
</html>`, timestamp)

	return html
}

// getDataLength 安全获取数据长度
func getDataLength(data *parse.ExtractResult, getter func(*parse.ExtractResult) int) int {
	if data == nil {
		return 0
	}
	return getter(data)
}

func getSpiderLength(spiderResult *SpiderResult) int {
	if spiderResult == nil {
		return 0
	}
	return len(spiderResult.URLs)
}

// extractFaviconURL 从HTML中提取网站图标URL
func extractFaviconURL(baseURL, htmlContent string) string {
	// 查找 favicon 链接
	patterns := []string{
		`<link[^>]+rel=["'](?:shortcut )?icon["'][^>]+href=["']([^"']+)["']`,
		`<link[^>]+href=["']([^"']+)["'][^>]+rel=["'](?:shortcut )?icon["']`,
		`<link[^>]+rel=["']apple-touch-icon["'][^>]+href=["']([^"']+)["']`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(htmlContent)
		if len(matches) > 1 {
			faviconURL := matches[1]
			// 如果是相对路径，转换为绝对路径
			if strings.HasPrefix(faviconURL, "//") {
				return "https:" + faviconURL
			} else if strings.HasPrefix(faviconURL, "/") {
				parsed, err := url.Parse(baseURL)
				if err == nil {
					return parsed.Scheme + "://" + parsed.Host + faviconURL
				}
			} else if strings.HasPrefix(faviconURL, "http") {
				return faviconURL
			}
		}
	}

	// 如果没有找到，尝试默认的 favicon.ico
	parsed, err := url.Parse(baseURL)
	if err == nil {
		return parsed.Scheme + "://" + parsed.Host + "/favicon.ico"
	}

	return ""
}
