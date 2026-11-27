package cmd

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Gh0xE9/EagleSword/config"
	"github.com/Gh0xE9/EagleSword/handler/parse"
	"github.com/Gh0xE9/EagleSword/handler/scanner"
	"github.com/Gh0xE9/EagleSword/handler/vuln"
	"github.com/Gh0xE9/EagleSword/payload"
)

type Config struct {
	URL          string
	File         string
	Render       bool
	Cookie       string
	Header       string
	Headers      map[string]string
	Cookies      string
	Spider       bool
	Threads      int
	Proxy        string
	Recursive    bool
	SSRF         bool
	SSRFMethod   string
	SSRFThreads  int
	SSRFTimeout  int
	SSRFPorts    string
	SSRFIPs      string
	SSRFOOB      string
	SSRFPostData string
	SSRFJSONData string
	XSS          bool
	XSSThreads   int
	XSSTimeout   int
	XSSPostData  string
	XSSJSONData  string
	AllVulns     bool
}

func ParseFlags() *Config {
	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		config.PrintBannerMultiColor()
		fmt.Println("\nOptions:")
		fmt.Println("  -u string")
		fmt.Println("        Target URL (start with http or https)")
		fmt.Println("  -f string")
		fmt.Println("        File path of targets (one per line, e.g. input.txt)")
		fmt.Println("  -t int")
		fmt.Println("        Number of concurrent threads (default 5)")
		fmt.Println("  -render")
		fmt.Println("        Use headless browser to render dynamic pages (default true)")
		fmt.Println("  -cookie string")
		fmt.Println("        custom cookies (e.g., 'session=abc123;user=admin')")
		fmt.Println("  -header string")
		fmt.Println("        Custom headers (e.g., 'Authorization: eXXXXXXXXX,X-Forwarded-for: 127.0.0.1')")
		fmt.Println("  -spider")
		fmt.Println("        Deep crawler test, it is not recommended to check it, as it will make a large number of requests to the website")
		fmt.Println("  -r")
		fmt.Println("        Recursive scanning: scan discovered directories recursively")
		fmt.Println("  -proxy string")
		fmt.Println("        Proxy server (e.g., 'http://user:pass@host:8080' or 'socks5://user:pass@host:8080')")
		fmt.Println("  -s")
		fmt.Println("        Enable SSRF vulnerability scanning")
		fmt.Println("  -smethod string")
		fmt.Println("        HTTP method for SSRF testing (default: GET)")
		fmt.Println("  -sthreads int")
		fmt.Println("        Number of concurrent threads for SSRF scanning (default: 10)")
		fmt.Println("  -stimeout int")
		fmt.Println("        Timeout in seconds for SSRF requests (default: 10)")
		fmt.Println("  -sports string")
		fmt.Println("        Custom ports for SSRF scanning (e.g., '80,443,8080' or '1-1000')")
		fmt.Println("  -sips string")
		fmt.Println("        Custom IPs for SSRF scanning (e.g., '192.168.1.1,10.0.0.1' or '192.168.1.0/24')")
		fmt.Println("  -soob string")
		fmt.Println("        OOB server URL for out-of-band detection")
		fmt.Println("  -spost string")
		fmt.Println("        POST data for parameterized SSRF testing (e.g., 'name=value&email=test@example.com')")
		fmt.Println("  -sjson string")
		fmt.Println("        JSON data for parameterized SSRF testing (e.g., '{\"name\":\"value\",\"email\":\"test@example.com\"}')")
		fmt.Println("  -x string")
		fmt.Println("        Enable XSS vulnerability scanning (set to 'yes' to enable)")
		fmt.Println("  -xthreads int")
		fmt.Println("        Number of concurrent threads for XSS scanning (default: 10)")
		fmt.Println("  -xtimeout int")
		fmt.Println("        Timeout in seconds for XSS requests (default: 10)")
		fmt.Println("  -xpost string")
		fmt.Println("        POST data for parameterized XSS testing (e.g., 'name=value&email=test@example.com')")
		fmt.Println("  -xjson string")
		fmt.Println("        JSON data for parameterized XSS testing (e.g., '{\"name\":\"value\",\"email\":\"test@example.com\"}')")
		fmt.Println("  -a string")
		fmt.Println("        Enable all vulnerability scanning (set to 'yes' to enable XSS + SSRF)")
		fmt.Println("  -h")
		fmt.Println("        Show basic help message and exit")
		os.Exit(0)
	}

	config.PrintBannerMultiColor()

	u := flag.String("u", "", "target URL (http or https)")
	f := flag.String("f", "", "file path of targets (one per line)")
	t := flag.Int("t", 5, "number of concurrent threads")
	render := flag.Bool("render", true, "use headless browser to render dynamic pages")
	cookie := flag.String("cookie", "", "custom cookies (e.g., 'session=abc123;user=admin')")
	header := flag.String("header", "", "custom headers (e.g., 'Authorization: Bearer 111,X-FF: 127.0.0.1')")
	spider := flag.Bool("spider", false, "enable site spidering to crawl all pages")
	recursive := flag.Bool("r", false, "recursive scanning: scan discovered directories recursively")
	proxy := flag.String("proxy", "", "proxy server (e.g., 'http://user:pass@proxy:8080' or 'socks5://user:pass@proxy:1080')")
	ssrf := flag.Bool("s", false, "enable SSRF vulnerability scanning")
	ssrfMethod := flag.String("smethod", "GET", "HTTP method for SSRF testing")
	ssrfThreads := flag.Int("sthreads", 10, "number of concurrent threads for SSRF scanning")
	ssrfTimeout := flag.Int("stimeout", 10, "timeout in seconds for SSRF requests")
	ssrfPorts := flag.String("sports", "", "custom ports for SSRF scanning")
	ssrfIPs := flag.String("sips", "", "custom IPs for SSRF scanning")
	ssrfOOB := flag.String("soob", "", "OOB server URL for out-of-band detection")
	ssrfPostData := flag.String("spost", "", "POST data for parameterized SSRF testing")
	ssrfJSONData := flag.String("sjson", "", "JSON data for parameterized SSRF testing")
	xss := flag.String("x", "", "Enable XSS vulnerability scanning (set to 'yes' to enable)")
	xssThreads := flag.Int("xthreads", 10, "Number of concurrent threads for XSS scanning")
	xsstimeout := flag.Int("xtimeout", 10, "Timeout in seconds for XSS requests")
	xssPostData := flag.String("xpost", "", "POST data for parameterized XSS testing")
	xssJSONData := flag.String("xjson", "", "JSON data for parameterized XSS testing")
	allVulns := flag.String("a", "", "Enable all vulnerability scanning (set to 'yes' to enable XSS + SSRF)")
	flag.Parse()

	customHeaders := parseHeaders(*header)
	customCookies := parseCookies(*cookie)

	// 处理 -a 参数逻辑
	enableAllVulns := *allVulns == "yes"
	enableSSRF := *ssrf || enableAllVulns
	enableXSS := *xss == "yes" || enableAllVulns

	return &Config{
		URL:          *u,
		File:         *f,
		Render:       *render,
		Cookie:       *cookie,
		Header:       *header,
		Headers:      customHeaders,
		Cookies:      customCookies,
		Spider:       *spider,
		Threads:      *t,
		Proxy:        *proxy,
		Recursive:    *recursive,
		SSRF:         enableSSRF,
		SSRFMethod:   *ssrfMethod,
		SSRFThreads:  *ssrfThreads,
		SSRFTimeout:  *ssrfTimeout,
		SSRFPorts:    *ssrfPorts,
		SSRFIPs:      *ssrfIPs,
		SSRFOOB:      *ssrfOOB,
		SSRFPostData: *ssrfPostData,
		SSRFJSONData: *ssrfJSONData,
		XSS:          enableXSS,
		XSSThreads:   *xssThreads,
		XSSTimeout:   *xsstimeout,
		XSSPostData:  *xssPostData,
		XSSJSONData:  *xssJSONData,
		AllVulns:     enableAllVulns,
	}
}

func (c *Config) GetTargets() []string {
	var targets []string

	if c.URL != "" {
		targets = append(targets, c.URL)
	}

	if c.File != "" {
		if lines, err := os.ReadFile(c.File); err == nil {
			for _, line := range strings.Split(string(lines), "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					urls := expandLineToURLs(line)
					targets = append(targets, urls...)
				}
			}
		}
	}

	return targets
}

func (c *Config) Run() {
	targets := c.GetTargets()

	if len(targets) == 0 {
		fmt.Println(config.ColorRed("[ERROR]"), "No scan target specified, please use -u or -f parameter")
		return
	}

	if len(targets) == 1 {
		fmt.Println(config.ColorCyan("[SCAN]"), "Start scanning a single target:", targets[0])

		// 显示启用的扫描类型
		if c.AllVulns {
			fmt.Println(config.ColorGreen("[INFO]"), "All vulnerability scanning enabled (XSS + SSRF)")
		} else {
			var enabledScans []string
			if c.SSRF {
				enabledScans = append(enabledScans, "SSRF")
			}
			if c.XSS {
				enabledScans = append(enabledScans, "XSS")
			}
			if len(enabledScans) > 0 {
				fmt.Println(config.ColorGreen("[INFO]"), "Enabled scans:", strings.Join(enabledScans, ", "))
			}
		}

		// 执行常规扫描
		if err := scanner.ProcessTarget(targets[0], c.Cookies, c.Headers, c.Spider, true, c.Proxy, c.Recursive); err != nil {
			fmt.Fprintln(os.Stderr, config.ColorRed("[ERROR]"), targets[0], err)
		}

		// 执行SSRF扫描
		if c.SSRF {
			c.runSSRFScan([]string{targets[0]})
		}

		// 执行XSS扫描
		if c.XSS {
			c.runXSSScan([]string{targets[0]})
		}
		return
	}

	if c.Threads <= 0 {
		c.Threads = 1
	} else if c.Threads > 50 {
		c.Threads = 50
		fmt.Println(config.ColorYellow("[WARNING]"), "The number of threads is too large and has been limited to 50")
	}

	fmt.Println(config.ColorCyan("[SCAN]"), fmt.Sprintf("Starting concurrent scan of %d targets, using %d threads", len(targets), c.Threads))

	// 显示启用的扫描类型
	if c.AllVulns {
		fmt.Println(config.ColorGreen("[INFO]"), "All vulnerability scanning enabled (XSS + SSRF)")
	} else {
		var enabledScans []string
		if c.SSRF {
			enabledScans = append(enabledScans, "SSRF")
		}
		if c.XSS {
			enabledScans = append(enabledScans, "XSS")
		}
		if len(enabledScans) > 0 {
			fmt.Println(config.ColorGreen("[INFO]"), "Enabled scans:", strings.Join(enabledScans, ", "))
		}
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	semaphore := make(chan struct{}, c.Threads)

	var successCount, errorCount int
	var errors []string

	for _, target := range targets {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			mu.Lock()
			fmt.Println(config.ColorCyan("[SCAN]"), "Start Scan:", t)
			mu.Unlock()

			if err := scanner.ProcessTarget(t, c.Cookies, c.Headers, c.Spider, false, c.Proxy, c.Recursive); err != nil {
				mu.Lock()
				errorCount++
				errors = append(errors, fmt.Sprintf("%s: %v", t, err))
				fmt.Fprintln(os.Stderr, config.ColorRed("[ERROR]"), t, err)
				mu.Unlock()
			} else {
				mu.Lock()
				successCount++
				fmt.Println(config.ColorGreen("[SUCCESS]"), "Scan Completed:", t)
				mu.Unlock()
			}
		}(target)
	}

	wg.Wait()

	mu.Lock()
	fmt.Println(config.ColorGreen("[COMPLETE]"), fmt.Sprintf("All targets scanned completed - Success: %d, Failure: %d", successCount, errorCount))
	if len(errors) > 0 {
		fmt.Println(config.ColorRed("[ERRORS]"), "Failed scan:")
		for _, err := range errors {
			fmt.Println("  -", err)
		}
	}
	mu.Unlock()

	// 执行SSRF扫描
	if c.SSRF {
		c.runSSRFScan(targets)
	}

	// 执行XSS扫描
	if c.XSS {
		c.runXSSScan(targets)
	}
}

// runSSRFScan 执行SSRF扫描
func (c *Config) runSSRFScan(targets []string) {
	fmt.Println(config.ColorCyan("[SSRF]"), "Starting SSRF vulnerability scanning...")

	// 解析配置
	internalIPs := c.parseSSRFIPs()
	customPorts := c.parseSSRFPorts()
	timeout := time.Duration(c.SSRFTimeout) * time.Second

	// 创建SSRF扫描器
	scanner := vuln.NewSSRFScanner(c.Headers, c.SSRFMethod, c.SSRFThreads, timeout)

	// 生成payload
	var allPayloads []payload.Payload

	// 添加端口扫描payload
	portScanPayloads := payload.GetPortScanPayloads(internalIPs, customPorts, true)
	allPayloads = append(allPayloads, portScanPayloads...)

	// 添加文件读取payload
	fileReadPayloads := payload.GetFileReadPayloads()
	allPayloads = append(allPayloads, fileReadPayloads...)

	// 添加OOB payload
	if c.SSRFOOB != "" {
		oobPayloads := payload.GetOOBPayloads(c.SSRFOOB)
		allPayloads = append(allPayloads, oobPayloads...)
	}

	fmt.Printf(config.ColorCyan("[SSRF]")+" Generated %d payloads for testing\n", len(allPayloads))

	// 并发扫描所有目标
	var wg sync.WaitGroup
	var mu sync.Mutex
	semaphore := make(chan struct{}, c.Threads)

	var totalResults []vuln.SSRFResult

	for _, target := range targets {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			mu.Lock()
			fmt.Println(config.ColorCyan("[SSRF]"), "Scanning:", t)
			mu.Unlock()

			var results []vuln.SSRFResult

			// 检查是否有POST或JSON数据，进行参数化扫描
			if c.SSRFPostData != "" || c.SSRFJSONData != "" {
				// 创建请求信息
				reqInfo := &parse.RequestInfo{
					URL:      t,
					Method:   c.SSRFMethod,
					Headers:  c.Headers,
					PostData: c.SSRFPostData,
					JSONData: c.SSRFJSONData,
				}

				results = scanner.ScanTargetWithParameters(reqInfo, allPayloads)
			} else {
				// 传统扫描方式
				results = scanner.ScanTarget(t, allPayloads)
			}

			mu.Lock()
			totalResults = append(totalResults, results...)
			mu.Unlock()
		}(target)
	}

	wg.Wait()

	// 打印结果
	if len(totalResults) > 0 {
		scanner.SetResults(totalResults)
		scanner.PrintResults()

		// 保存结果到文件
		filename := fmt.Sprintf("ssrf_results_%s.txt", time.Now().Format("20060102_150405"))
		if err := scanner.SaveResults(filename); err != nil {
			fmt.Println(config.ColorRed("[ERROR]"), "Failed to save SSRF results:", err)
		} else {
			fmt.Println(config.ColorGreen("[SUCCESS]"), "SSRF results saved to:", filename)
		}
	} else {
		fmt.Println(config.ColorYellow("[SSRF]"), "No SSRF vulnerabilities found")
	}
}

// parseSSRFIPs 解析SSRF扫描的IP列表
func (c *Config) parseSSRFIPs() []string {
	if c.SSRFIPs == "" {
		return []string{}
	}

	var ips []string

	// 支持逗号分隔的IP列表和CIDR网段
	parts := strings.Split(c.SSRFIPs, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// 检查是否是CIDR格式
		if strings.Contains(part, "/") {
			cidrIPs, err := vuln.ParseCIDR(part)
			if err != nil {
				fmt.Println(config.ColorRed("[ERROR]"), "Invalid CIDR:", part, err)
				continue
			}
			ips = append(ips, cidrIPs...)
		} else {
			ips = append(ips, part)
		}
	}

	return ips
}

// parseSSRFPorts 解析SSRF扫描的端口列表
func (c *Config) parseSSRFPorts() []int {
	if c.SSRFPorts == "" {
		return []int{}
	}

	var ports []int

	// 支持逗号分隔的端口列表和端口范围
	parts := strings.Split(c.SSRFPorts, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// 检查是否是端口范围
		if strings.Contains(part, "-") {
			rangePorts, err := vuln.ParsePortRange(part)
			if err != nil {
				fmt.Println(config.ColorRed("[ERROR]"), "Invalid port range:", part, err)
				continue
			}
			ports = append(ports, rangePorts...)
		} else {
			port, err := strconv.Atoi(part)
			if err != nil {
				fmt.Println(config.ColorRed("[ERROR]"), "Invalid port:", part, err)
				continue
			}
			ports = append(ports, port)
		}
	}

	return ports
}

// runXSSScan 执行XSS扫描
func (c *Config) runXSSScan(targets []string) {
	fmt.Println(config.ColorCyan("[XSS]"), "Starting XSS vulnerability scanning...")

	// 解析配置
	timeout := time.Duration(c.XSSTimeout) * time.Second

	// 创建XSS扫描器
	scanner := vuln.NewXSSScanner(c.Headers, c.XSSThreads, timeout)

	// 获取XSS payloads
	payloads := vuln.GetXSSPayloads()

	fmt.Printf(config.ColorCyan("[XSS]")+" Generated %d payloads for testing\n", len(payloads))

	// 并发扫描所有目标
	var wg sync.WaitGroup
	var mu sync.Mutex
	semaphore := make(chan struct{}, c.Threads)

	var totalResults []vuln.XSSResult

	for _, target := range targets {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			mu.Lock()
			fmt.Println(config.ColorCyan("[XSS]"), "Scanning:", t)
			mu.Unlock()

			var results []vuln.XSSResult

			// 检查是否有POST或JSON数据，进行参数化扫描
			if c.XSSPostData != "" || c.XSSJSONData != "" {
				// 创建请求信息
				reqInfo := &parse.RequestInfo{
					URL:      t,
					Method:   "GET",
					Headers:  c.Headers,
					PostData: c.XSSPostData,
					JSONData: c.XSSJSONData,
				}

				results = scanner.ScanTargetWithParameters(reqInfo, payloads)
			} else {
				// 传统扫描方式
				results = scanner.ScanTarget(t, payloads)
			}

			mu.Lock()
			totalResults = append(totalResults, results...)
			mu.Unlock()
		}(target)
	}

	wg.Wait()

	// 打印结果
	if len(totalResults) > 0 {
		scanner.SetResults(totalResults)
		scanner.PrintResults()

		// 保存结果到文件
		filename := fmt.Sprintf("xss_results_%s.txt", time.Now().Format("20060102_150405"))
		if err := scanner.SaveResults(filename); err != nil {
			fmt.Println(config.ColorRed("[ERROR]"), "Failed to save XSS results:", err)
		} else {
			fmt.Println(config.ColorGreen("[SUCCESS]"), "XSS results saved to:", filename)
		}
	} else {
		fmt.Println(config.ColorYellow("[XSS]"), "No XSS vulnerabilities found")
	}
}

func parseHeaders(headerStr string) map[string]string {
	headers := make(map[string]string)
	if headerStr == "" {
		return headers
	}

	headerPairs := strings.Split(headerStr, ",")
	for _, pair := range headerPairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		parts := strings.SplitN(pair, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			if key != "" && value != "" {
				headers[key] = value
			}
		}
	}

	return headers
}

func parseCookies(cookieStr string) string {
	if cookieStr == "" {
		return ""
	}
	return strings.TrimSpace(cookieStr)
}

func expandLineToURLs(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
		return []string{line}
	}
	return []string{"http://" + line, "https://" + line}
}
