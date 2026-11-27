package scanner

import (
	"fmt"
	htmlpkg "html"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// GenerateAssetHTMLReport 生成资产收集HTML报告
func GenerateAssetHTMLReport(query string, assets []AssetInfo, outputFile string) error {
	// 创建输出目录
	outputDir := "output/assets"
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// 生成文件名
	if outputFile == "" {
		timestamp := time.Now().Format("20060102_150405")
		outputFile = fmt.Sprintf("asset_report_%s.html", timestamp)
	}
	filepath := filepath.Join(outputDir, outputFile)

	// 生成HTML内容
	htmlContent := generateAssetHTMLContent(query, assets)

	// 写入文件
	if err := os.WriteFile(filepath, []byte(htmlContent), 0644); err != nil {
		return fmt.Errorf("failed to write HTML file: %w", err)
	}

	fmt.Printf("Asset HTML report generated: %s\n", filepath)
	return nil
}

// generateAssetHTMLContent 生成资产收集HTML内容
func generateAssetHTMLContent(query string, assets []AssetInfo) string {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	
	html := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EagleSword 资产收集报告</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }

        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 300;
        }

        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
        }

        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }

        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
            transition: transform 0.3s ease;
        }

        .stat-card:hover {
            transform: translateY(-5px);
        }

        .stat-number {
            display: block;
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 5px;
        }

        .stat-label {
            color: #666;
            font-size: 0.9em;
        }

        .query-info {
            padding: 20px 30px;
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            margin: 0 30px 20px 30px;
            border-radius: 0 8px 8px 0;
        }

        .query-info h3 {
            color: #1976d2;
            margin-bottom: 10px;
        }

        .query-info .query-text {
            font-family: 'Courier New', monospace;
            background: white;
            padding: 10px;
            border-radius: 5px;
            border: 1px solid #ddd;
        }

        .table-container {
            margin: 30px;
            overflow-x: auto;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
        }

        .data-table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            font-size: 0.9em;
        }

        .data-table th {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 10px;
            text-align: left;
            font-weight: 600;
            position: sticky;
            top: 0;
            z-index: 10;
        }

        .data-table td {
            padding: 12px 10px;
            border-bottom: 1px solid #eee;
            vertical-align: top;
        }

        .data-table tr:hover {
            background: #f8f9fa;
        }

        .data-table tr:nth-child(even) {
            background: #fafafa;
        }

        .data-table tr:nth-child(even):hover {
            background: #f0f0f0;
        }

        .url-cell {
            max-width: 200px;
            word-break: break-all;
        }

        .url-cell a {
            color: #667eea;
            text-decoration: none;
        }

        .url-cell a:hover {
            text-decoration: underline;
        }

        .status-badge {
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: 600;
            text-align: center;
            min-width: 50px;
            display: inline-block;
        }

        .status-200 { background: #e8f5e8; color: #2e7d32; }
        .status-300 { background: #fff3e0; color: #f57c00; }
        .status-400 { background: #ffebee; color: #d32f2f; }
        .status-500 { background: #fce4ec; color: #c2185b; }

        .source-badge {
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: 600;
            text-align: center;
            min-width: 60px;
            display: inline-block;
        }

        .source-fofa { background: #e3f2fd; color: #1976d2; }
        .source-quake { background: #e8f5e8; color: #2e7d32; }
        .source-hunter { background: #fff3e0; color: #f57c00; }

        .footer {
            padding: 30px;
            text-align: center;
            color: #666;
            background: #f8f9fa;
            border-top: 1px solid #eee;
        }

        .export-btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 25px;
            cursor: pointer;
            font-size: 1em;
            font-weight: 600;
            transition: all 0.3s ease;
            margin: 20px;
        }

        .export-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
        }

        .copy-all-btn {
            background: #28a745;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 20px;
            cursor: pointer;
            font-size: 0.9em;
            font-weight: 600;
            transition: all 0.3s ease;
            margin-left: 10px;
        }

        .copy-all-btn:hover {
            background: #218838;
            transform: translateY(-1px);
        }

        .table-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }

        .table-header h2 {
            margin: 0;
            color: #333;
        }

        @media (max-width: 768px) {
            .container {
                margin: 10px;
                border-radius: 10px;
            }
            
            .header {
                padding: 20px;
            }
            
            .header h1 {
                font-size: 2em;
            }
            
            .stats {
                grid-template-columns: repeat(2, 1fr);
                padding: 20px;
            }
            
            .table-container {
                margin: 20px;
            }
            
            .data-table {
                font-size: 0.8em;
            }
            
            .data-table th,
            .data-table td {
                padding: 8px 5px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ EagleSword</h1>
            <div class="subtitle">资产收集报告</div>
        </div>

        <div class="stats">
            <div class="stat-card">
                <span class="stat-number">` + strconv.Itoa(len(assets)) + `</span>
                <span class="stat-label">总资产数量</span>
            </div>
            <div class="stat-card">
                <span class="stat-number">` + strconv.Itoa(countAssetsBySource(assets, "Fofa")) + `</span>
                <span class="stat-label">Fofa 资产</span>
            </div>
            <div class="stat-card">
                <span class="stat-number">` + strconv.Itoa(countAssetsBySource(assets, "360 Quake")) + `</span>
                <span class="stat-label">360 Quake 资产</span>
            </div>
            <div class="stat-card">
                <span class="stat-number">` + strconv.Itoa(countAssetsBySource(assets, "Hunter")) + `</span>
                <span class="stat-label">Hunter 资产</span>
            </div>
        </div>

        <div class="query-info">
            <h3>🔍 查询语句</h3>
            <div class="query-text">` + htmlpkg.EscapeString(query) + `</div>
        </div>

        <div class="table-container">
            <div class="table-header">
                <h2>📊 资产详情</h2>
                <button class="copy-all-btn" onclick="copyAllAssets()">复制所有URL</button>
            </div>
            <table class="data-table">
                <thead>
                    <tr>
                        <th style="width: 5%;">序号</th>
                        <th style="width: 20%;">URL</th>
                        <th style="width: 10%;">IP</th>
                        <th style="width: 5%;">端口</th>
                        <th style="width: 8%;">协议</th>
                        <th style="width: 12%;">网站标题</th>
                        <th style="width: 6%;">响应码</th>
                        <th style="width: 8%;">产品应用</th>
                        <th style="width: 8%;">网站服务</th>
                        <th style="width: 8%;">网站路径</th>
                        <th style="width: 8%;">地理位置</th>
                        <th style="width: 8%;">更新时间</th>
                        <th style="width: 6%;">ASN</th>
                        <th style="width: 8%;">运营商</th>
                        <th style="width: 8%;">ICP备案号</th>
                        <th style="width: 6%;">数据来源</th>
                    </tr>
                </thead>
                <tbody>`

	// 添加表格数据
	for _, asset := range assets {
		// 确定响应码样式
		statusClass := ""
		if asset.ResponseCode >= 200 && asset.ResponseCode < 300 {
			statusClass = "status-200"
		} else if asset.ResponseCode >= 300 && asset.ResponseCode < 400 {
			statusClass = "status-300"
		} else if asset.ResponseCode >= 400 && asset.ResponseCode < 500 {
			statusClass = "status-400"
		} else if asset.ResponseCode >= 500 {
			statusClass = "status-500"
		}

		// 确定数据来源样式
		sourceClass := ""
		switch asset.Source {
		case "Fofa":
			sourceClass = "source-fofa"
		case "360 Quake":
			sourceClass = "source-quake"
		case "Hunter":
			sourceClass = "source-hunter"
		}

		html += `
                    <tr>
                        <td>` + strconv.Itoa(asset.Index) + `</td>
                        <td class="url-cell"><a href="` + htmlpkg.EscapeString(asset.URL) + `" target="_blank">` + htmlpkg.EscapeString(asset.URL) + `</a></td>
                        <td>` + htmlpkg.EscapeString(asset.IP) + `</td>
                        <td>` + htmlpkg.EscapeString(asset.Port) + `</td>
                        <td>` + htmlpkg.EscapeString(asset.Protocol) + `</td>
                        <td>` + htmlpkg.EscapeString(asset.Title) + `</td>
                        <td><span class="status-badge ` + statusClass + `">` + strconv.Itoa(asset.ResponseCode) + `</span></td>
                        <td>` + htmlpkg.EscapeString(asset.Product) + `</td>
                        <td>` + htmlpkg.EscapeString(asset.Service) + `</td>
                        <td>` + htmlpkg.EscapeString(asset.Path) + `</td>
                        <td>` + htmlpkg.EscapeString(asset.Location) + `</td>
                        <td>` + htmlpkg.EscapeString(asset.UpdateTime) + `</td>
                        <td>` + htmlpkg.EscapeString(asset.ASN) + `</td>
                        <td>` + htmlpkg.EscapeString(asset.Operator) + `</td>
                        <td>` + htmlpkg.EscapeString(asset.ICPNumber) + `</td>
                        <td><span class="source-badge ` + sourceClass + `">` + htmlpkg.EscapeString(asset.Source) + `</span></td>
                    </tr>`
	}

	html += `
                </tbody>
            </table>
        </div>

        <div style="text-align: center; padding: 20px;">
            <button class="export-btn" onclick="exportToCSV()">📥 导出CSV</button>
            <button class="export-btn" onclick="exportToJSON()">📄 导出JSON</button>
        </div>

        <div class="footer">
            <p>报告生成时间: ` + timestamp + `</p>
            <p>EagleSword Asset Collection Report | Generated by EagleSword</p>
        </div>
    </div>

    <script>
        // 复制所有资产URL
        function copyAllAssets() {
            const rows = document.querySelectorAll('.data-table tbody tr');
            let allUrls = '';
            
            rows.forEach(function(row) {
                const urlCell = row.cells[1]; // URL列
                if (urlCell) {
                    const url = urlCell.textContent.trim();
                    if (url) {
                        allUrls += url + '\\n';
                    }
                }
            });
            
            navigator.clipboard.writeText(allUrls).then(function() {
                alert('所有URL已复制到剪贴板！');
            }).catch(function(err) {
                console.error('复制失败:', err);
                // 降级方案
                const textArea = document.createElement('textarea');
                textArea.value = allUrls;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                alert('所有URL已复制到剪贴板！');
            });
        }

        // 导出CSV
        function exportToCSV() {
            const table = document.querySelector('.data-table');
            const rows = Array.from(table.querySelectorAll('tr'));
            
            let csv = '';
            rows.forEach(function(row) {
                const cells = Array.from(row.querySelectorAll('th, td'));
                const rowData = cells.map(function(cell) {
                    return '"' + cell.textContent.trim().replace(/"/g, '""') + '"';
                });
                csv += rowData.join(',') + '\\n';
            });
            
            const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
            const link = document.createElement('a');
            const url = URL.createObjectURL(blob);
            link.setAttribute('href', url);
            link.setAttribute('download', 'assets_' + new Date().toISOString().slice(0,10) + '.csv');
            link.style.visibility = 'hidden';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }

        // 导出JSON
        function exportToJSON() {
            const table = document.querySelector('.data-table');
            const headers = Array.from(table.querySelectorAll('thead th')).map(th => th.textContent.trim());
            const rows = Array.from(table.querySelectorAll('tbody tr'));
            
            const data = rows.map(function(row) {
                const cells = Array.from(row.querySelectorAll('td'));
                const obj = {};
                headers.forEach(function(header, index) {
                    obj[header] = cells[index] ? cells[index].textContent.trim() : '';
                });
                return obj;
            });
            
            const json = JSON.stringify(data, null, 2);
            const blob = new Blob([json], { type: 'application/json;charset=utf-8;' });
            const link = document.createElement('a');
            const url = URL.createObjectURL(blob);
            link.setAttribute('href', url);
            link.setAttribute('download', 'assets_' + new Date().toISOString().slice(0,10) + '.json');
            link.style.visibility = 'hidden';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }

        // 表格排序功能
        function sortTable(columnIndex) {
            const table = document.querySelector('.data-table');
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            
            rows.sort(function(a, b) {
                const aText = a.cells[columnIndex].textContent.trim();
                const bText = b.cells[columnIndex].textContent.trim();
                
                // 尝试数字比较
                const aNum = parseFloat(aText);
                const bNum = parseFloat(bText);
                
                if (!isNaN(aNum) && !isNaN(bNum)) {
                    return aNum - bNum;
                }
                
                // 字符串比较
                return aText.localeCompare(bText);
            });
            
            rows.forEach(function(row) {
                tbody.appendChild(row);
            });
        }

        // 为表头添加点击排序
        document.addEventListener('DOMContentLoaded', function() {
            const headers = document.querySelectorAll('.data-table th');
            headers.forEach(function(header, index) {
                header.style.cursor = 'pointer';
                header.addEventListener('click', function() {
                    sortTable(index);
                });
            });
        });
    </script>
</body>
</html>`

	return html
}

// countAssetsBySource 统计指定来源的资产数量
func countAssetsBySource(assets []AssetInfo, source string) int {
	count := 0
	for _, asset := range assets {
		if asset.Source == source {
			count++
		}
	}
	return count
}
