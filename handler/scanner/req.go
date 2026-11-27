package scanner

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Gh0xE9/EagleSword/config"
	"github.com/Gh0xE9/EagleSword/handler/parse"
	"github.com/Gh0xE9/EagleSword/handler/vuln"
)

// 全局互斥锁，保护文件系统操作和输出操作
var (
	fileMutex   sync.Mutex
	outputMutex sync.Mutex
)

// ProcessTarget 处理单个目标 URL 的抓取、解析与保存流程
func ProcessTarget(target string, cookies string, headers map[string]string, spider bool, autoOpenBrowser bool, proxy string, recursive bool) error {
	// 初始化日志记录器
	if err := InitLogger(target); err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	defer CloseLogger()

	LogInfo("Start scanning the target: %s", target)

	parsed, err := url.Parse(target)
	if err != nil {
		LogError("URL parsing failed: %v", err)
		return fmt.Errorf("URL parsing failed: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		LogError("Unsupported protocol: %s", parsed.Scheme)
		return fmt.Errorf("unsupported protocol: %s", parsed.Scheme)
	}

	// 计算保存目录：output/<scheme>_<host>_<port>/
	outDir := buildOutputDir(parsed)

	// 使用文件锁保护目录创建
	fileMutex.Lock()
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fileMutex.Unlock()
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	jsDir := filepath.Join(outDir, "js")
	jsmapDir := filepath.Join(outDir, "jsmap")
	otherDir := filepath.Join(outDir, "other")
	_ = os.MkdirAll(jsDir, 0o755)
	_ = os.MkdirAll(jsmapDir, 0o755)
	_ = os.MkdirAll(otherDir, 0o755)
	fileMutex.Unlock()

	// HTTP 直连抓取
	LogInfo("Starting HTTP request: %s", parsed.String())
	res, err := WebFetch(parsed.String(), cookies, headers, proxy)
	if err != nil {
		LogError("HTTP access failed: %v", err)
		return fmt.Errorf("HTTP access failed: %w", err)
	}
	LogHTTP("GET", parsed.String(), res.Status, len(res.Body), res.UserAgent)

	title := extractTitle(res.Body)
	LogInfo("Page title: %s", title)

	// 使用输出锁保护控制台输出
	outputMutex.Lock()
	fmt.Printf("%s %s status=%d title=%q length=%d\n", config.ColorCyan("[HTTP]"), parsed.String(), res.Status, title, len(res.Body))
	outputMutex.Unlock()

	// 保存 HTML 页面
	htmlName := safeNameFromURL(parsed.String(), ".html")
	fileMutex.Lock()
	_ = os.WriteFile(filepath.Join(outDir, htmlName), []byte(res.Body), 0o644)
	fileMutex.Unlock()

	// 提取并打印首页中的所有 URL
	var extractedURLs []string
	if all, err := parse.ExtractAllURLs(parsed.String(), res.Body); err == nil {
		extractedURLs = all
		outputMutex.Lock()
		for _, u := range all {
			fmt.Println(config.ColorGreen("[URL]"), u)
		}
		outputMutex.Unlock()
	}

	// 使用浏览器渲染获取动态加载的 JS 文件（如果启用）
	var browserResult *BrowserResult
	if config.BrowserConfig.Enabled {
		outputMutex.Lock()
		fmt.Println(config.ColorCyan("[BROWSER]"), "Start browser rendering...")
		outputMutex.Unlock()

		var err error
		browserResult, err = RenderWithBrowser(parsed.String(), headers)
		if err != nil {
			outputMutex.Lock()
			// 检查是否是超时错误，提供更友好的提示
			if strings.Contains(err.Error(), "超时") || strings.Contains(err.Error(), "timeout") {
				fmt.Fprintf(os.Stderr, "%s Browser rendering timeout (%v): %v\n", config.ColorYellow("[WARN]"), config.BrowserConfig.Timeout, err)
				fmt.Fprintf(os.Stderr, "%s Continuing with static analysis only...\n", config.ColorCyan("[INFO]"))
			} else if strings.Contains(err.Error(), "网络连接失败") || strings.Contains(err.Error(), "net::") {
				fmt.Fprintf(os.Stderr, "%s Network connection failed: %v\n", config.ColorRed("[ERROR]"), err)
				fmt.Fprintf(os.Stderr, "%s Continuing with static analysis only...\n", config.ColorCyan("[INFO]"))
			} else if strings.Contains(err.Error(), "SSL证书错误") || strings.Contains(err.Error(), "certificate") {
				fmt.Fprintf(os.Stderr, "%s SSL certificate error: %v\n", config.ColorRed("[ERROR]"), err)
				fmt.Fprintf(os.Stderr, "%s Continuing with static analysis only...\n", config.ColorCyan("[INFO]"))
			} else {
				fmt.Fprintf(os.Stderr, "%s Browser rendering failure: %v\n", config.ColorRed("[ERROR]"), err)
				fmt.Fprintf(os.Stderr, "%s Continuing with static analysis only...\n", config.ColorCyan("[INFO]"))
			}
			outputMutex.Unlock()
		} else {
			outputMutex.Lock()
			fmt.Printf("%s rendering completed, %d JS files found\n", config.ColorCyan("[BROWSER]"), len(browserResult.JSFiles))
			outputMutex.Unlock()

			// 处理浏览器渲染获取的 JS 文件
			for _, jsURL := range browserResult.JSFiles {
				outputMutex.Lock()
				fmt.Println(config.ColorBlue("[JS-BROWSER]"), jsURL)
				outputMutex.Unlock()

				// 获取 JS 内容
				jsContent, exists := browserResult.JSContent[jsURL]
				if !exists {
					// 如果浏览器没有获取到内容，回退到 HTTP 抓取
					if jsBytes, _, _, err := FetchBytes(jsURL, cookies, headers, proxy); err == nil {
						jsContent = string(jsBytes)
					} else {
						continue
					}
				}

				// 格式化 JS 代码
				formattedJS := parse.FormatJS(jsContent)

				// 保存格式化后的 JS 文件
				jsName := safeNameFromURL(jsURL, ".js")
				fileMutex.Lock()
				_ = os.WriteFile(filepath.Join(jsDir, jsName), []byte(formattedJS), 0o644)
				fileMutex.Unlock()

				// 敏感信息扫描
				findings := parse.ExtractSecretFindings(jsURL, jsContent)
				outputMutex.Lock()
				for _, fd := range findings {
					fmt.Printf("%s %s %s:%d\n", config.ColorRed("[SECRET]"), config.ColorYellow(fd.Field), fd.File, fd.Line)
				}
				outputMutex.Unlock()

				// 尝试解析 sourceMappingURL
				if mapURL := findSourceMapURL(jsURL, jsContent); mapURL != "" {
					if mbytes, _, _, err := FetchBytes(mapURL, cookies, headers, proxy); err == nil {
						// 检查是否是有效的 JSON 格式（以 { 开头）
						mapContent := strings.TrimSpace(string(mbytes))
						if strings.HasPrefix(mapContent, "{") {
							// 提取标题
							title := extractTitle(mapContent)
							response := mapContent
							if len(response) > 50 {
								response = response[:50] + "..."
							}

							// 输出详细结果
							fmt.Printf("%s %s %s %s %s %s %s %s %s\n",
								config.ColorMagenta("[JSMAP]"),
								config.ColorYellow("path:"), config.ColorGreen(mapURL),
								config.ColorYellow("title:"), config.ColorGreen(title),
								config.ColorYellow("length:"), config.ColorBlue(fmt.Sprintf("%d", len(mbytes))),
								config.ColorYellow("response:"), config.ColorRed(response))

							mapName := safeNameFromURL(mapURL, ".map")
							_ = os.WriteFile(filepath.Join(jsmapDir, mapName), mbytes, 0o644)
						}
					}
				} else {
					// 回退：尝试 .js.map 约定
					if mu, err := url.Parse(jsURL); err == nil {
						base := mu.Path
						if strings.HasSuffix(strings.ToLower(base), ".js") {
							mu.Path = strings.TrimSuffix(base, filepath.Ext(base)) + ".js.map"
							mapURL := mu.String()
							if mbytes, _, _, err := FetchBytes(mapURL, cookies, headers, proxy); err == nil {
								// 检查是否是有效的 JSON 格式（以 { 开头）
								mapContent := strings.TrimSpace(string(mbytes))
								if strings.HasPrefix(mapContent, "{") {
									// 提取标题
									title := extractTitle(mapContent)
									response := mapContent
									if len(response) > 50 {
										response = response[:50] + "..."
									}

									// 输出详细结果
									fmt.Printf("%s %s %s %s %s %s %s %s %s\n",
										config.ColorMagenta("[JSMAP]"),
										config.ColorYellow("path:"), config.ColorGreen(mapURL),
										config.ColorYellow("title:"), config.ColorGreen(title),
										config.ColorYellow("length:"), config.ColorBlue(fmt.Sprintf("%d", len(mbytes))),
										config.ColorYellow("response:"), config.ColorRed(response))

									mapName := safeNameFromURL(mapURL, ".map")
									_ = os.WriteFile(filepath.Join(jsmapDir, mapName), mbytes, 0o644)
								}
							}
						}
					}
				}
			}
		}
	}

	// 处理静态 JS 文件
	jsURLs, err := parse.ExtractJSURLs(parsed.String(), res.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s JS URL extraction failed: %v\n", config.ColorRed("[ERROR]"), err)
	} else {
		// 记录已处理的 JS 文件（避免重复处理）
		processedJS := make(map[string]bool)
		if browserResult != nil {
			for _, jsURL := range browserResult.JSFiles {
				processedJS[jsURL] = true
			}
		}

		for _, j := range jsURLs {
			// 检查是否已经被浏览器处理过
			alreadyProcessed := processedJS[j]
			if alreadyProcessed {
				continue
			}

			fmt.Println(config.ColorBlue("[JS-STATIC]"), j)
			if jsBytes, _, _, err := FetchBytes(j, cookies, headers, proxy); err == nil {
				// 格式化 JS 代码
				formattedJS := parse.FormatJS(string(jsBytes))

				// 保存格式化后的 JS 文件
				jsName := safeNameFromURL(j, ".js")
				_ = os.WriteFile(filepath.Join(jsDir, jsName), []byte(formattedJS), 0o644)

				// 敏感信息扫描
				findings := parse.ExtractSecretFindings(j, string(jsBytes))
				for _, fd := range findings {
					fmt.Printf("%s %s %s:%d\n", config.ColorRed("[SECRET]"), config.ColorYellow(fd.Field), fd.File, fd.Line)
				}

				// 尝试解析 sourceMappingURL
				if mapURL := findSourceMapURL(j, string(jsBytes)); mapURL != "" {
					if mbytes, _, _, err := FetchBytes(mapURL, cookies, headers, proxy); err == nil {
						// 检查是否是有效的 JSON 格式（以 { 开头）
						mapContent := strings.TrimSpace(string(mbytes))
						if strings.HasPrefix(mapContent, "{") {
							// 提取标题
							title := extractTitle(mapContent)
							response := mapContent
							if len(response) > 50 {
								response = response[:50] + "..."
							}

							// 输出详细结果
							fmt.Printf("%s %s %s %s %s %s %s %s %s\n",
								config.ColorMagenta("[JSMAP]"),
								config.ColorYellow("path:"), config.ColorGreen(mapURL),
								config.ColorYellow("title:"), config.ColorGreen(title),
								config.ColorYellow("length:"), config.ColorBlue(fmt.Sprintf("%d", len(mbytes))),
								config.ColorYellow("response:"), config.ColorRed(response))

							mapName := safeNameFromURL(mapURL, ".map")
							_ = os.WriteFile(filepath.Join(jsmapDir, mapName), mbytes, 0o644)
						}
					}
				} else {
					// 回退：尝试 .js.map 约定
					if mu, err := url.Parse(j); err == nil {
						base := mu.Path
						if strings.HasSuffix(strings.ToLower(base), ".js") {
							mu.Path = strings.TrimSuffix(base, filepath.Ext(base)) + ".js.map"
							mapURL := mu.String()
							if mbytes, _, _, err := FetchBytes(mapURL, cookies, headers, proxy); err == nil {
								// 检查是否是有效的 JSON 格式（以 { 开头）
								mapContent := strings.TrimSpace(string(mbytes))
								if strings.HasPrefix(mapContent, "{") {
									// 提取标题
									title := extractTitle(mapContent)
									response := mapContent
									if len(response) > 100 {
										response = response[:100] + "..."
									}

									// 输出详细结果
									fmt.Printf("%s %s %s %s %s %s %s %s %s\n",
										config.ColorMagenta("[JSMAP]"),
										config.ColorYellow("path:"), config.ColorGreen(mapURL),
										config.ColorYellow("title:"), config.ColorGreen(title),
										config.ColorYellow("length:"), config.ColorBlue(fmt.Sprintf("%d", len(mbytes))),
										config.ColorYellow("response:"), config.ColorRed(response))

									mapName := safeNameFromURL(mapURL, ".map")
									_ = os.WriteFile(filepath.Join(jsmapDir, mapName), mbytes, 0o644)
								}
							}
						}
					}
				}
			}
		}
	}

	// 综合数据提取
	fmt.Println(config.ColorCyan("[EXTRACT]"), "BUG HUNTING NOW...")

	// 从 HTML 中提取数据
	LogInfo("Start extracting data from HTML")
	htmlData := parse.ExtractAllData(res.Body)
	// 为 HTML 内容也提取 SECRET 信息
	htmlData.SecretFindings = parse.ExtractSecretFindings(target, res.Body)
	htmlData.PathFindings = parse.ExtractPathsWithFile(target, res.Body)

	// 将浏览器JS文件中的敏感信息合并到htmlData中
	if browserResult != nil {
		var browserSecretFindings []parse.SecretFinding
		for _, jsURL := range browserResult.JSFiles {
			if jsContent, exists := browserResult.JSContent[jsURL]; exists {
				findings := parse.ExtractSecretFindings(jsURL, jsContent)
				browserSecretFindings = append(browserSecretFindings, findings...)
			}
		}
		if len(browserSecretFindings) > 0 {
			htmlData.SecretFindings = append(htmlData.SecretFindings, browserSecretFindings...)
		}
	}

	// 记录敏感信息发现
	for _, secret := range htmlData.SecretFindings {
		LogSecret("Sensitive Information", secret.Field, secret.File, secret.Line)
	}

	LogInfo("HTML data extraction completed - URL: %d, Domain: %d, IP: %d, Email: %d, Phone: %d, Path: %d",
		len(htmlData.URL), len(htmlData.Domain), len(htmlData.IP),
		len(htmlData.Mail), len(htmlData.Mobile), len(htmlData.Path))

	// 从浏览器渲染的 JS 文件中提取数据
	var jsData *parse.ExtractResult
	if browserResult != nil {
		LogInfo("Start extracting data from JS files, total %d JS files", len(browserResult.JSContent))
		jsData = &parse.ExtractResult{}
		for jsURL, jsContent := range browserResult.JSContent {
			LogInfo("Processing JS file: %s", jsURL)
			jsExtract := parse.ExtractAllData(jsContent)
			// 添加带文件名的密钥信息
			jsExtract.SecretFindings = parse.ExtractSecretFindings(jsURL, jsContent)
			// 添加带文件名的路径信息
			jsExtract.PathFindings = parse.ExtractPathsWithFile(jsURL, jsContent)

			// 记录JS文件中的敏感信息发现
			for _, secret := range jsExtract.SecretFindings {
				LogSecret("Sensitive Information", secret.Field, secret.File, secret.Line)
			}

			jsData = mergeExtractResults(jsData, jsExtract)
		}
		LogInfo("JS data extraction completed - URL: %d, Domain: %d, IP: %d, Email: %d, Mobile: %d, Path: %d",
			len(jsData.URL), len(jsData.Domain), len(jsData.IP),
			len(jsData.Mail), len(jsData.Mobile), len(jsData.Path))
	}

	// 合并所有提取结果
	finalData := mergeExtractResults(htmlData, jsData)

	// 如果启用爬虫，进行站点爬虫
	var spiderData *parse.ExtractResult
	if spider {
		LogInfo("Start site crawling")
		spiderResult, err := Spider(parsed.String(), cookies, headers, proxy)
		if err != nil {
			LogError("Crawler failed: %v", err)
			fmt.Fprintf(os.Stderr, "%s crawler failed: %v\n", config.ColorRed("[ERROR]"), err)
		} else {
			LogInfo("Crawling completed, found %d URLs", len(spiderResult.URLs))

			// 记录爬虫发现的URL
			for _, url := range spiderResult.URLs {
				LogSpider(url, 200) // 假设爬虫成功的URL都是200状态
			}

			spiderData = spiderResult.AllData
			// 合并爬虫数据
			finalData = mergeExtractResults(finalData, spiderData)

			// 保存爬虫结果
			saveSpiderResults(outDir, spiderResult)
			LogInfo("Crawler data saving completed")
		}
	}

	// 输出提取结果到控制台
	outputExtractResults(finalData)

	// API 端点测试
	fmt.Println(config.ColorCyan("[API-TEST]"), "STARTING REQUESTING API ENDPOINTS...")

	// 收集所有 API 端点
	var apiEndpoints []string

	// 从路径发现中提取 API 端点
	for _, pf := range finalData.PathFindings {
		if isLikelyAPIEndpoint(pf.Path) {
			// 确保路径包含完整的域名
			fullURL := buildFullAPIURL(parsed.String(), pf.Path)
			if fullURL != "" {
				apiEndpoints = append(apiEndpoints, fullURL)
			}
		}
	}

	// 从 URL 中提取 API 端点
	for _, url := range finalData.URL {
		if isLikelyAPIEndpoint(url) {
			// URL 可能已经是完整的，但确保它包含域名
			if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
				apiEndpoints = append(apiEndpoints, url)
			} else {
				fullURL := buildFullAPIURL(parsed.String(), url)
				if fullURL != "" {
					apiEndpoints = append(apiEndpoints, fullURL)
				}
			}
		}
	}

	// 去重
	apiEndpoints = removeDuplicateStrings(apiEndpoints)

	// 测试 API 端点
	var apiResults []parse.APIResult
	if len(apiEndpoints) > 0 {
		LogInfo("Started testing %d API endpoints", len(apiEndpoints))
		apiResults = parse.TestAPIEndpoints(parsed.String(), apiEndpoints, cookies, headers, proxy)

		// 记录API测试结果
		for _, result := range apiResults {
			LogAPI(result.URL, result.Method, result.Status)
		}

		parse.OutputAPIResults(apiResults)

		// 保存 API 测试结果到文件
		saveAPIResults(outDir, apiResults)
		LogInfo("API testing completed, %d endpoints tested in total", len(apiResults))
	} else {
		LogInfo("API endpoint not found")
		fmt.Println(config.ColorYellow("[API-TEST]"), "API endpoint not found")
	}

	// 目录探测
	fmt.Println(config.ColorCyan("[DIRECTORY]"), "STARTING DIRECTORY SCANNING...")
	LogInfo("Start directory detection")
	directoryResults := scanCommonDirectories(parsed.String(), cookies, headers, proxy)
	LogInfo("Directory detection completed, %d paths tested in total", len(directoryResults))

	// 递归扫描
	if recursive {
		fmt.Println(config.ColorCyan("[RECURSIVE]"), "STARTING RECURSIVE SCANNING...")
		LogInfo("Start recursive scanning")
		recursiveResults := performRecursiveScan(parsed.String(), directoryResults, cookies, headers, proxy)
		LogInfo("Recursive scanning completed, %d additional paths scanned", len(recursiveResults))

		// 将递归扫描结果合并到目录结果中
		directoryResults = append(directoryResults, recursiveResults...)
	}

	// 指纹识别
	fmt.Println(config.ColorCyan("[FINGERPRINT]"), "STARTING FINGERPRINT SCANNING...")
	LogInfo("Start fingerprint detection")

	// 构建响应头字符串用于指纹匹配
	var responseHeaders strings.Builder
	for key, values := range res.Headers {
		for _, value := range values {
			responseHeaders.WriteString(strings.ToLower(key))
			responseHeaders.WriteString(": ")
			responseHeaders.WriteString(value)
			responseHeaders.WriteString("\n")
		}
	}

	fingerprintResults := performFingerprintScan(parsed.String(), res.Body, responseHeaders.String())
	LogInfo("Fingerprint detection completed, %d fingerprints matched", len(fingerprintResults))

	// CORS漏洞检测
	fmt.Println(config.ColorCyan("[CORS]"), "STARTING CORS VULNERABILITY SCANNING...")
	LogInfo("Start CORS vulnerability detection")

	// 从API端点中提取路径部分用于CORS检测
	var corsEndpoints []string
	for _, endpoint := range apiEndpoints {
		// 提取路径部分
		if parsedURL, err := url.Parse(endpoint); err == nil {
			corsEndpoints = append(corsEndpoints, parsedURL.Path)
		}
	}

	corsResult, err := vuln.CheckCORS(parsed.String(), corsEndpoints, proxy)
	if err != nil {
		outputMutex.Lock()
		fmt.Printf("%s CORS detection failed: %v\n", config.ColorRed("[ERROR]"), err)
		outputMutex.Unlock()
		LogError("CORS detection failed: %v", err)
		corsResult = nil
	} else {
		vuln.OutputCORSResult(corsResult)
		if corsResult.IsVulnerable {
			LogInfo("CORS vulnerability detected: %s", corsResult.VulnerabilityReason)
			// 发送飞书通知
			if err := vuln.SendCORSFeishuNotification(corsResult); err != nil {
				outputMutex.Lock()
				fmt.Printf("%s Failed to send CORS Feishu notification: %v\n", config.ColorYellow("[WARN]"), err)
				outputMutex.Unlock()
				LogError("Failed to send CORS Feishu notification: %v", err)
			} else {
				outputMutex.Lock()
				fmt.Printf("%s CORS vulnerability notification sent to Feishu\n", config.ColorGreen("[SUCCESS]"))
				outputMutex.Unlock()
				LogInfo("CORS vulnerability notification sent to Feishu")
			}
		} else {
			LogInfo("No CORS vulnerability detected")
		}
	}

	// 保存提取结果到文件
	saveExtractResults(outDir, finalData)

	// 生成 HTML 报告
	var spiderResult *SpiderResult
	if spider && spiderData != nil {
		// 重新获取爬虫结果用于 HTML 报告
		spiderResult, _ = Spider(parsed.String(), cookies, headers, proxy)
	} else {
		// 即使没有启用爬虫功能，也创建一个包含目标URL和提取URL的结果
		allURLs := []string{parsed.String()}
		// 添加从页面中提取的URL
		allURLs = append(allURLs, extractedURLs...)

		spiderResult = &SpiderResult{
			URLs:    allURLs,
			Pages:   make(map[string]*HTTPResult),
			JSFiles: make(map[string]string),
			AllData: &parse.ExtractResult{},
		}
		spiderResult.Pages[parsed.String()] = &res
	}
	generateHTMLReport(outDir, parsed.String(), &res, finalData, apiResults, spiderResult, directoryResults, fingerprintResults, corsResult)

	// 自动打开浏览器显示HTML报告（仅在单目标扫描时）
	if autoOpenBrowser {
		// 使用与generateHTMLReport相同的命名规则
		timestamp := time.Now().Format("20060102_150405")
		siteName := parsed.Hostname()
		reportName := fmt.Sprintf("eaglesword_%s_%s.html", timestamp, siteName)
		htmlPath := filepath.Join(outDir, reportName)

		// 检查文件是否存在
		if _, err := os.Stat(htmlPath); os.IsNotExist(err) {
			outputMutex.Lock()
			fmt.Printf("%s HTML report file not found: %s\n", config.ColorRed("[ERROR]"), htmlPath)
			outputMutex.Unlock()
		} else {
			if err := openBrowser(htmlPath); err != nil {
				outputMutex.Lock()
				fmt.Printf("%s Failed to open browser: %v\n", config.ColorYellow("[WARN]"), err)
				outputMutex.Unlock()
			} else {
				outputMutex.Lock()
				fmt.Printf("%s HTML report opened in browser: %s\n", config.ColorGreen("[SUCCESS]"), htmlPath)
				outputMutex.Unlock()
			}
		}
	}

	// 发送飞书通知
	fmt.Println(config.ColorCyan("[NOTIFY]"), "Send Lark notification...")
	LogInfo("Start sending Lark notifications")
	scanResult := CreateScanResult(parsed.String(), finalData, apiResults, spiderResult)
	if err := SendFeishuNotification(scanResult); err != nil {
		LogError("Feishu notification failed to send: %v", err)
		fmt.Println(config.ColorRed("[ERROR]"), "Feishu notification failed to send:", err)
	} else {
		LogInfo("Feishu notification sent successfully")
		fmt.Println(config.ColorGreen("[SUCCESS]"), "Feishu notification sent successfully")
	}

	// 记录扫描总结
	jsCount := countJSFilesInDir(outDir)
	jsmapCount := countJSMAPFilesInDir(outDir)

	LogSummary(fmt.Sprintf("Scan Completed - URL: %d, Domain: %d, IP: %d, Email: %d, Phone: %d, Path: %d, Sensitive Information: %d, API Endpoint: %d, JS File: %d, JSMAP File: %d",
		len(finalData.URL), len(finalData.Domain), len(finalData.IP),
		len(finalData.Mail), len(finalData.Mobile), len(finalData.Path),
		len(finalData.SecretFindings), len(apiResults), jsCount, jsmapCount))

	LogInfo("Scan completed, log file: %s", GetLogPath())

	return nil
}

// 辅助函数：从 URL 构建输出目录名
func buildOutputDir(parsed *url.URL) string {
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return fmt.Sprintf("output/%s_%s_%s", parsed.Scheme, host, port)
}

// 辅助函数：从 URL 生成安全的文件名
func safeNameFromURL(urlStr, ext string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return "unknown" + ext
	}

	// 使用路径的最后一部分作为文件名
	path := parsed.Path
	if path == "" || path == "/" {
		path = "/index"
	}

	// 提取文件名
	parts := strings.Split(path, "/")
	filename := parts[len(parts)-1]
	if filename == "" {
		filename = "index"
	}

	// 清理文件名，移除不安全字符
	filename = strings.ReplaceAll(filename, ":", "_")
	filename = strings.ReplaceAll(filename, "?", "_")
	filename = strings.ReplaceAll(filename, "&", "_")
	filename = strings.ReplaceAll(filename, "=", "_")
	filename = strings.ReplaceAll(filename, "/", "_")
	filename = strings.ReplaceAll(filename, "\\", "_")

	// 限制文件名长度
	if len(filename) > 50 {
		filename = filename[:50]
	}

	return filename + ext
}

// 辅助函数：从 JS 内容中查找 sourceMappingURL
func findSourceMapURL(jsURL, jsContent string) string {
	lines := strings.Split(jsContent, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if strings.Contains(line, "sourceMappingURL") {
			// 查找 sourceMappingURL 的值
			if idx := strings.Index(line, "sourceMappingURL="); idx != -1 {
				value := line[idx+len("sourceMappingURL="):]
				value = strings.TrimSpace(value)
				// 移除可能的引号
				value = strings.Trim(value, `"'`)
				if value != "" {
					// 如果是相对路径，转换为绝对路径
					if !strings.HasPrefix(value, "http") {
						if parsed, err := url.Parse(jsURL); err == nil {
							if resolved, err := parsed.Parse(value); err == nil {
								return resolved.String()
							}
						}
					}
					return value
				}
			}
		}
	}
	return ""
}

// 提取页面标题
func extractTitle(html string) string {
	// 简单的标题提取
	start := strings.Index(html, "<title>")
	if start == -1 {
		return ""
	}
	start += 7
	end := strings.Index(html[start:], "</title>")
	if end == -1 {
		return ""
	}
	return strings.TrimSpace(html[start : start+end])
}

// 合并提取结果
func mergeExtractResults(data1, data2 *parse.ExtractResult) *parse.ExtractResult {
	if data1 == nil {
		return data2
	}
	if data2 == nil {
		return data1
	}

	return &parse.ExtractResult{
		SFZ:            appendUnique(data1.SFZ, data2.SFZ...),
		Mobile:         appendUnique(data1.Mobile, data2.Mobile...),
		Mail:           appendUnique(data1.Mail, data2.Mail...),
		IP:             appendUnique(data1.IP, data2.IP...),
		IPPort:         appendUnique(data1.IPPort, data2.IPPort...),
		Domain:         appendUnique(data1.Domain, data2.Domain...),
		Path:           appendUnique(data1.Path, data2.Path...),
		IncompletePath: appendUnique(data1.IncompletePath, data2.IncompletePath...),
		URL:            appendUnique(data1.URL, data2.URL...),
		JWT:            appendUnique(data1.JWT, data2.JWT...),
		Algorithm:      appendUnique(data1.Algorithm, data2.Algorithm...),
		Secret:         appendUnique(data1.Secret, data2.Secret...),
		SecretFindings: appendSecretFindings(data1.SecretFindings, data2.SecretFindings...),
		PathFindings:   appendPathFindings(data1.PathFindings, data2.PathFindings),
	}
}

// 添加唯一元素到切片
func appendUnique(slice []string, elements ...string) []string {
	seen := make(map[string]bool)
	result := slice

	for _, elem := range slice {
		seen[elem] = true
	}

	for _, elem := range elements {
		if !seen[elem] {
			seen[elem] = true
			result = append(result, elem)
		}
	}

	return result
}

// 添加唯一的 SecretFinding 到切片
func appendSecretFindings(slice []parse.SecretFinding, elements ...parse.SecretFinding) []parse.SecretFinding {
	seen := make(map[string]bool)
	result := slice

	for _, elem := range slice {
		key := elem.File + ":" + elem.Field + ":" + fmt.Sprintf("%d", elem.Line)
		seen[key] = true
	}

	for _, elem := range elements {
		key := elem.File + ":" + elem.Field + ":" + fmt.Sprintf("%d", elem.Line)
		if !seen[key] {
			seen[key] = true
			result = append(result, elem)
		}
	}

	return result
}

// 合并路径发现结果，去重
func appendPathFindings(slice1, slice2 []parse.PathFinding) []parse.PathFinding {
	seen := make(map[string]bool)
	var result []parse.PathFinding

	// 添加第一个切片
	for _, item := range slice1 {
		key := item.File + ":" + item.Path + ":" + fmt.Sprintf("%d", item.Line)
		if !seen[key] {
			result = append(result, item)
			seen[key] = true
		}
	}

	// 添加第二个切片
	for _, item := range slice2 {
		key := item.File + ":" + item.Path + ":" + fmt.Sprintf("%d", item.Line)
		if !seen[key] {
			result = append(result, item)
			seen[key] = true
		}
	}

	return result
}

// 输出提取结果到控制台
func outputExtractResults(data *parse.ExtractResult) {
	if data == nil {
		return
	}

	// 身份证号
	for _, sfz := range data.SFZ {
		fmt.Println(config.ColorRed("[SFZ]"), sfz)
	}

	// 手机号
	for _, mobile := range data.Mobile {
		fmt.Println(config.ColorGreen("[MOBILE]"), mobile)
	}

	// 邮箱
	for _, mail := range data.Mail {
		fmt.Println(config.ColorBlue("[MAIL]"), mail)
	}

	// IP地址
	for _, ip := range data.IP {
		fmt.Println(config.ColorYellow("[IP]"), ip)
	}

	// IP:端口
	for _, ipPort := range data.IPPort {
		fmt.Println(config.ColorMagenta("[IP:PORT]"), ipPort)
	}

	// 域名
	for _, domain := range data.Domain {
		fmt.Println(config.ColorCyan("[DOMAIN]"), domain)
	}

	// 路径（带文件信息）
	for _, pf := range data.PathFindings {
		fmt.Printf("%s %s %s:%d\n", config.ColorGreen("[PATH]"), config.ColorYellow(pf.Path), pf.File, pf.Line)
	}

	// 不完整路径
	for _, incompletePath := range data.IncompletePath {
		fmt.Println(config.ColorBlue("[INCOMPLETE_PATH]"), incompletePath)
	}

	// URL
	for _, url := range data.URL {
		fmt.Println(config.ColorYellow("[URL]"), url)
	}

	// JWT Token
	for _, jwt := range data.JWT {
		fmt.Println(config.ColorMagenta("[JWT]"), jwt)
	}

	// 加密算法
	for _, algorithm := range data.Algorithm {
		fmt.Println(config.ColorCyan("[ALGORITHM]"), algorithm)
	}

	// 密钥（带文件信息）
	for _, fd := range data.SecretFindings {
		fmt.Printf("%s %s %s:%d\n", config.ColorRed("[SECRET]"), config.ColorYellow(fd.Field), fd.File, fd.Line)
	}
}

// 保存提取结果到文件
func saveExtractResults(outDir string, data *parse.ExtractResult) {
	if data == nil {
		return
	}

	// 保存各种类型的数据到文件
	saveToFile(filepath.Join(outDir, "sfz.txt"), data.SFZ)
	saveToFile(filepath.Join(outDir, "mobile.txt"), data.Mobile)
	saveToFile(filepath.Join(outDir, "mail.txt"), data.Mail)
	saveToFile(filepath.Join(outDir, "ips.txt"), data.IP)
	saveToFile(filepath.Join(outDir, "ip_ports.txt"), data.IPPort)
	saveToFile(filepath.Join(outDir, "domains.txt"), data.Domain)
	saveToFile(filepath.Join(outDir, "paths.txt"), data.Path)
	saveToFile(filepath.Join(outDir, "incomplete_paths.txt"), data.IncompletePath)
	saveToFile(filepath.Join(outDir, "urls.txt"), data.URL)
	saveToFile(filepath.Join(outDir, "jwts.txt"), data.JWT)
	saveToFile(filepath.Join(outDir, "algorithms.txt"), data.Algorithm)
	saveToFile(filepath.Join(outDir, "secrets.txt"), data.Secret)
}

// 保存字符串切片到文件
func saveToFile(filename string, data []string) {
	if len(data) == 0 {
		return
	}
	content := strings.Join(data, "\n")
	_ = os.WriteFile(filename, []byte(content), 0o644)
}

// saveAPIResults 保存 API 测试结果到文件
func saveAPIResults(outDir string, results []parse.APIResult) {
	if len(results) == 0 {
		return
	}

	// 创建 API 结果目录
	apiDir := filepath.Join(outDir, "api")
	_ = os.MkdirAll(apiDir, 0o755)

	// 保存详细的 API 测试结果
	var apiDetails []string
	for _, result := range results {
		path := extractPathFromURL(result.URL)
		detail := fmt.Sprintf("[API] path:%s length:%d method:%s response:%s title:%s url:%s status:%d",
			path, result.Length, result.Method, result.Response, result.Title, result.URL, result.Status)
		apiDetails = append(apiDetails, detail)
	}
	saveToFile(filepath.Join(apiDir, "api_results.txt"), apiDetails)

	// 保存 API 端点列表
	var endpoints []string
	seen := make(map[string]bool)
	for _, result := range results {
		path := extractPathFromURL(result.URL)
		if !seen[path] {
			endpoints = append(endpoints, path)
			seen[path] = true
		}
	}
	saveToFile(filepath.Join(apiDir, "api_endpoints.txt"), endpoints)

	// 保存按方法分类的结果
	var getResults, postResults []string
	for _, result := range results {
		path := extractPathFromURL(result.URL)
		detail := fmt.Sprintf("%s - status:%d length:%d response:%s",
			path, result.Status, result.Length, result.Response)

		if result.Method == "GET" {
			getResults = append(getResults, detail)
		} else if result.Method == "POST" {
			postResults = append(postResults, detail)
		}
	}
	saveToFile(filepath.Join(apiDir, "get_results.txt"), getResults)
	saveToFile(filepath.Join(apiDir, "post_results.txt"), postResults)

	// 保存状态码统计
	statusStats := make(map[int]int)
	for _, result := range results {
		statusStats[result.Status]++
	}
	var statusDetails []string
	for status, count := range statusStats {
		statusDetails = append(statusDetails, fmt.Sprintf("%d: %d", status, count))
	}
	saveToFile(filepath.Join(apiDir, "status_stats.txt"), statusDetails)
}

// extractPathFromURL 从 URL 中提取路径部分
func extractPathFromURL(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}
	return parsed.Path
}

// isLikelyAPIEndpoint 判断是否是可能的 API 端点
func isLikelyAPIEndpoint(path string) bool {
	// 检查是否包含 API 相关关键词
	apiKeywords := []string{
		"/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/auth", "/token",
		"/login", "/logout", "/register", "/user", "/admin", "/upload",
		"/download", "/search", "/query", "/data", "/json", "/xml",
	}

	lowerPath := strings.ToLower(path)
	for _, keyword := range apiKeywords {
		if strings.Contains(lowerPath, keyword) {
			return true
		}
	}

	// 检查是否是常见的 API 路径模式
	if strings.HasPrefix(path, "/api") || strings.HasPrefix(path, "/v") {
		return true
	}

	return false
}

// removeDuplicateStrings 去除重复字符串
func removeDuplicateStrings(slice []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

// countJSFilesInDir 统计指定目录中的JS文件数量
func countJSFilesInDir(baseDir string) int {
	jsDir := filepath.Join(baseDir, "js")

	// 检查目录是否存在
	if _, err := os.Stat(jsDir); os.IsNotExist(err) {
		return 0
	}

	// 读取目录中的文件
	files, err := os.ReadDir(jsDir)
	if err != nil {
		return 0
	}

	count := 0
	for _, file := range files {
		if !file.IsDir() && (strings.HasSuffix(file.Name(), ".js") || strings.HasSuffix(file.Name(), ".js.map")) {
			count++
		}
	}

	return count
}

// countJSMAPFilesInDir 统计指定目录中的JSMAP文件数量
func countJSMAPFilesInDir(baseDir string) int {
	jsmapDir := filepath.Join(baseDir, "jsmap")

	// 检查目录是否存在
	if _, err := os.Stat(jsmapDir); os.IsNotExist(err) {
		return 0
	}

	// 读取目录中的文件
	files, err := os.ReadDir(jsmapDir)
	if err != nil {
		return 0
	}

	count := 0
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".js.map") {
			count++
		}
	}

	return count
}

// buildFullAPIURL 构建完整的API URL
func buildFullAPIURL(baseURL, endpoint string) string {
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		return endpoint
	}

	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}

	// 如果endpoint不是以/开头，添加/
	if !strings.HasPrefix(endpoint, "/") {
		endpoint = "/" + endpoint
	}

	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}

	fullURL := base.ResolveReference(endpointURL)
	return fullURL.String()
}

// DirectoryResult 目录探测结果
type DirectoryResult struct {
	URL      string
	Title    string
	Length   int
	Response string
	Status   int
}

// scanCommonDirectories 扫描常见目录（并发优化版本）
func scanCommonDirectories(baseURL string, cookies string, headers map[string]string, proxyURL string) []DirectoryResult {
	var results []DirectoryResult

	// 创建支持代理的Transport
	transport, err := createProxyTransport(proxyURL)
	if err != nil {
		fmt.Printf("Failed to create proxy transport for directory scan: %v\n", err)
		return results
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   config.HTTPConfig.Timeout,
	}

	// 准备并发请求
	var requests []ConcurrentRequest
	for _, path := range config.CommonPaths {
		fullURL := buildFullAPIURL(baseURL, path)
		if fullURL == "" {
			continue
		}

		requests = append(requests, ConcurrentRequest{
			URL:     fullURL,
			Method:  "GET",
			Headers: headers,
			Cookies: cookies,
			Client:  client,
		})
	}

	// 执行并发请求
	responses := ExecuteConcurrentRequests(requests)

	// 处理响应结果
	for _, resp := range responses {
		if resp.Error != nil {
			// 跳过超时和网络错误
			if IsTimeoutError(resp.Error) || IsNetworkError(resp.Error) {
				continue
			}
			// 记录其他错误但不中断扫描
			fmt.Printf("Directory scan error for %s: %v\n", resp.URL, resp.Error)
			continue
		}

		if resp.StatusCode == 200 {
			// 读取响应体
			body, err := io.ReadAll(resp.Response.Body)
			resp.Response.Body.Close()

			if err != nil {
				continue
			}

			// 提取标题
			title := extractTitle(string(body))

			// 限制response长度并去掉换行符
			response := string(body)
			response = strings.ReplaceAll(response, "\n", " ")
			response = strings.ReplaceAll(response, "\r", " ")
			response = strings.ReplaceAll(response, "\t", " ")
			// 压缩多个空格为单个空格
			for strings.Contains(response, "  ") {
				response = strings.ReplaceAll(response, "  ", " ")
			}
			// 限制长度
			if len(response) > 100 {
				response = response[:100] + "..."
			}

			result := DirectoryResult{
				URL:      resp.URL,
				Title:    title,
				Length:   len(body),
				Response: response,
				Status:   resp.StatusCode,
			}

			results = append(results, result)

			// 输出结果
			fmt.Printf("%s %s %s %s %s %s %s %s %s %s %s\n",
				config.ColorCyan("[DIRECTORY]"),
				config.ColorYellow("path:"), config.ColorGreen(resp.URL),
				config.ColorYellow("title:"), config.ColorGreen(title),
				config.ColorYellow("length:"), config.ColorBlue(fmt.Sprintf("%d", len(body))),
				config.ColorYellow("code:"), config.ColorBlue(fmt.Sprintf("%d", resp.StatusCode)),
				config.ColorYellow("response:"), config.ColorRed(response))
			// 记录到日志
			LogDirectory(resp.URL, title, len(body), response)
		}
	}

	return results
}

// performFingerprintScan 执行指纹扫描（使用已解析的数据）
func performFingerprintScan(targetURL string, responseText string, responseHeaders string) []FingerprintResult {
	// 加载嵌入的指纹规则
	fingerprints, err := LoadFingerprints()
	if err != nil {
		outputMutex.Lock()
		fmt.Printf("%s Failed to load fingerprints: %v\n", config.ColorRed("[ERROR]"), err)
		outputMutex.Unlock()
		return nil
	}

	// 执行指纹匹配（使用已解析的数据）
	results := MatchFingerprints(targetURL, responseText, responseHeaders, fingerprints)

	return results
}

// openBrowser 打开浏览器显示HTML报告
func openBrowser(htmlPath string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", htmlPath)
	case "darwin":
		cmd = exec.Command("open", htmlPath)
	case "linux":
		cmd = exec.Command("xdg-open", htmlPath)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	return cmd.Start()
}

// performRecursiveScan 执行递归扫描
func performRecursiveScan(baseURL string, directoryResults []DirectoryResult, cookies string, headers map[string]string, proxy string) []DirectoryResult {
	var recursiveResults []DirectoryResult

	// 从目录扫描结果中提取发现的目录
	var discoveredDirs []string
	for _, result := range directoryResults {
		if result.Status == 200 || result.Status == 403 { // 200表示目录存在，403可能表示目录存在但禁止访问
			// 提取目录路径
			if parsedURL, err := url.Parse(result.URL); err == nil {
				dirPath := parsedURL.Path
				if dirPath != "/" && dirPath != "" {
					discoveredDirs = append(discoveredDirs, dirPath)
				}
			}
		}
	}

	// 去重
	discoveredDirs = removeDuplicateStrings(discoveredDirs)

	// 创建HTTP客户端
	transport, err := createProxyTransport(proxy)
	if err != nil {
		fmt.Printf("Failed to create proxy transport for recursive scan: %v\n", err)
		return recursiveResults
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   config.HTTPConfig.Timeout,
	}

	// 对每个发现的目录进行递归扫描
	for _, dir := range discoveredDirs {
		LogInfo("Recursively scanning directory: %s", dir)

		// 生成子目录和文件的常见名称
		subPaths := generateSubPaths(dir)

		// 准备并发请求
		var requests []ConcurrentRequest
		for _, subPath := range subPaths {
			fullURL := baseURL + subPath

			// 检查URL是否已经扫描过
			alreadyScanned := false
			for _, existing := range directoryResults {
				if existing.URL == fullURL {
					alreadyScanned = true
					break
				}
			}

			if !alreadyScanned {
				requests = append(requests, ConcurrentRequest{
					URL:     fullURL,
					Method:  "GET",
					Headers: headers,
					Cookies: cookies,
					Client:  client,
				})
			}
		}

		// 执行并发请求
		responses := ExecuteConcurrentRequests(requests)

		// 处理响应结果
		for _, resp := range responses {
			if resp.Error != nil {
				// 跳过超时和网络错误
				if IsTimeoutError(resp.Error) || IsNetworkError(resp.Error) {
					continue
				}
				continue
			}

			// 读取响应体
			body, err := io.ReadAll(resp.Response.Body)
			resp.Response.Body.Close()

			if err != nil {
				continue
			}

			// 提取标题
			title := extractTitle(string(body))

			result := DirectoryResult{
				URL:      resp.URL,
				Title:    title,
				Length:   len(body),
				Response: string(body),
				Status:   resp.StatusCode,
			}

			recursiveResults = append(recursiveResults, result)

			// 输出结果
			outputMutex.Lock()
			fmt.Printf("%s %s [%d] %s\n",
				config.ColorGreen("[RECURSIVE]"),
				resp.URL,
				resp.StatusCode,
				title)
			outputMutex.Unlock()
		}
	}

	return recursiveResults
}

// generateSubPaths 为给定目录生成常见的子路径
func generateSubPaths(baseDir string) []string {
	var paths []string

	// 确保目录路径以/结尾
	if !strings.HasSuffix(baseDir, "/") {
		baseDir += "/"
	}

	// 常见的子目录和文件
	commonItems := []string{
		"admin", "administrator", "login", "dashboard", "panel", "control",
		"api", "v1", "v2", "api/v1", "api/v2", "rest", "graphql",
		"backup", "backups", "bak", "old", "temp", "tmp", "test", "dev",
		"config", "configuration", "settings", "setup", "install",
		"upload", "uploads", "files", "images", "media", "static",
		"css", "js", "js/", "css/", "images/", "assets/",
		"index.php", "index.html", "index.asp", "index.jsp",
		"readme.txt", "readme.md", "robots.txt", "sitemap.xml",
		".git", ".svn", ".env", "config.php", "config.json",
		"phpinfo.php", "info.php", "test.php", "debug.php",
	}

	for _, item := range commonItems {
		paths = append(paths, baseDir+item)
	}

	return paths
}
