package scanner

import (
	"bytes"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	htmlpkg "html"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Gh0xE9/EagleSword/config"
)

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// AssetInfo 资产信息结构
type AssetInfo struct {
	Index        int    `json:"index"`         // 序号
	URL          string `json:"url"`           // URL
	IP           string `json:"ip"`            // IP地址
	Port         string `json:"port"`          // 端口
	Protocol     string `json:"protocol"`      // 协议名
	Title        string `json:"title"`         // 网站标题
	ICPNumber    string `json:"icp_number"`    // ICP备案号
	Source       string `json:"source"`        // 数据来源平台
	ResponseCode int    `json:"response_code"` // 响应码
	Product      string `json:"product"`       // 产品应用
	Service      string `json:"service"`       // 网站服务
	Path         string `json:"path"`          // 网站路径
	Location     string `json:"location"`      // 地理位置
	UpdateTime   string `json:"update_time"`   // 更新时间
	ASN          string `json:"asn"`           // ASN
	Operator     string `json:"operator"`      // 运营商
	// Fofa特有字段
	Host string `json:"host"` // 主机名
	// 360 Quake特有字段
	Domain         string `json:"domain"`           // 域名
	OS             string `json:"os"`               // 操作系统
	Country        string `json:"country"`          // 国家
	Province       string `json:"province"`         // 省份
	City           string `json:"city"`             // 城市
	Company        string `json:"company"`          // 公司
	IsWeb          string `json:"is_web"`           // 是否Web资产
	IsRisk         string `json:"is_risk"`          // 是否风险
	IsRiskProtocol string `json:"is_risk_protocol"` // 是否风险协议
	ASOrg          string `json:"as_org"`           // AS组织
	ISP            string `json:"isp"`              // ISP
	Banner         string `json:"banner"`           // Banner
	Header         string `json:"header"`           // Header
	BaseProtocol   string `json:"base_protocol"`    // 基础协议
	// Hunter特有字段
	WebTitle     string `json:"web_title"`     // Web标题
	Number       string `json:"number"`        // 编号
	ConsumeQuota string `json:"consume_quota"` // 消耗积分
	RestQuota    string `json:"rest_quota"`    // 剩余积分
	// 原始数据字段 - 保存所有API返回的原始字段
	RawData map[string]interface{} `json:"raw_data"` // 原始数据
}

// AssetCollector 资产收集器
type AssetCollector struct {
	FofaEmail string
	FofaKey   string
	QuakeKey  string
	HunterKey string
	Query     string
	Count     int  // 每个平台获取的数据数量
	AllAssets bool // 自动拉取所有资产数据，不需要用户确认
	client    *http.Client
}

// NewAssetCollector 创建新的资产收集器
func NewAssetCollector(fofaEmail, fofaKey, quakeKey, hunterKey, query string, count int, allAssets bool) *AssetCollector {
	return &AssetCollector{
		FofaEmail: fofaEmail,
		FofaKey:   fofaKey,
		QuakeKey:  quakeKey,
		HunterKey: hunterKey,
		Query:     query,
		Count:     count,
		AllAssets: allAssets,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// CollectAssets 收集所有平台的资产信息
func (ac *AssetCollector) CollectAssets() error {
	fmt.Println(config.ColorCyan("[ASSET]"), "Starting asset collection from multiple platforms...")

	var allAssets []AssetInfo
	var fofaAssets, quakeAssets, hunterAssets []AssetInfo
	index := 1

	// 收集Fofa数据
	fmt.Println(config.ColorBlue("[FOFA]"), "Collecting data from Fofa...")
	fofaAssets, err := ac.collectFofaDataWithPagination(!ac.AllAssets)
	if err != nil {
		fmt.Printf("%s Fofa collection failed: %v\n", config.ColorRed("[ERROR]"), err)
	} else {
		for _, asset := range fofaAssets {
			asset.Index = index
			asset.Source = "Fofa"
			allAssets = append(allAssets, asset)
			index++
		}
		fmt.Printf("%s Collected %d assets from Fofa\n", config.ColorGreen("[SUCCESS]"), len(fofaAssets))
	}

	// 收集360 Quake数据
	fmt.Println(config.ColorBlue("[QUAKE]"), "Collecting data from 360 Quake...")
	quakeAssets, err = ac.collectQuakeDataWithPagination(!ac.AllAssets)
	if err != nil {
		fmt.Printf("%s Quake collection failed: %v\n", config.ColorRed("[ERROR]"), err)
	} else {
		for _, asset := range quakeAssets {
			asset.Index = index
			asset.Source = "360 Quake"
			allAssets = append(allAssets, asset)
			index++
		}
		fmt.Printf("%s Collected %d assets from 360 Quake\n", config.ColorGreen("[SUCCESS]"), len(quakeAssets))
	}

	// 收集Hunter数据
	fmt.Println(config.ColorBlue("[HUNTER]"), "Collecting data from Hunter...")
	hunterAssets, err = ac.collectHunterDataWithPagination(!ac.AllAssets)
	if err != nil {
		fmt.Printf("%s Hunter collection failed: %v\n", config.ColorRed("[ERROR]"), err)
	} else {
		for _, asset := range hunterAssets {
			asset.Index = index
			asset.Source = "Hunter"
			allAssets = append(allAssets, asset)
			index++
		}
		fmt.Printf("%s Collected %d assets from Hunter\n", config.ColorGreen("[SUCCESS]"), len(hunterAssets))
	}

	// 去重处理
	uniqueAssets := ac.deduplicateAssets(allAssets)

	// 保存CSV数据
	if err := ac.saveAssets(uniqueAssets); err != nil {
		return fmt.Errorf("failed to save assets: %w", err)
	}

	// 生成HTML报告（按照资产扫描的格式）
	if err := ac.generateAssetScanReport(uniqueAssets, fofaAssets, quakeAssets, hunterAssets); err != nil {
		fmt.Printf("%s Failed to generate HTML report: %v\n", config.ColorRed("[ERROR]"), err)
	} else {
		fmt.Printf("%s HTML report generated successfully\n", config.ColorGreen("[SUCCESS]"))
	}

	fmt.Printf("%s Total collected %d unique assets\n", config.ColorGreen("[SUCCESS]"), len(uniqueAssets))
	return nil
}

// collectFofaData 收集Fofa数据
func (ac *AssetCollector) collectFofaData() ([]AssetInfo, error) {
	return ac.collectFofaDataWithPagination(false)
}

// collectFofaDataWithPagination 收集Fofa数据（支持分页）
func (ac *AssetCollector) collectFofaDataWithPagination(confirmContinue bool) ([]AssetInfo, error) {
	// Base64编码查询语句
	queryBase64 := base64.StdEncoding.EncodeToString([]byte(ac.Query))

	// 先获取总数信息
	totalAPIURL := fmt.Sprintf("https://fofa.info/api/v1/search/all?email=%s&key=%s&qbase64=%s&size=1&fields=host,ip,port,protocol,title,icp",
		url.QueryEscape(ac.FofaEmail),
		url.QueryEscape(ac.FofaKey),
		url.QueryEscape(queryBase64))

	resp, err := ac.client.Get(totalAPIURL)
	if err != nil {
		return nil, fmt.Errorf("failed to request Fofa API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		fmt.Printf("%s Fofa API Error Response: %s\n", config.ColorRed("[DEBUG]"), string(bodyBytes))
		return nil, fmt.Errorf("Fofa API returned status code: %d, response: %s", resp.StatusCode, string(bodyBytes))
	}

	// 读取响应体用于调试
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// 打印调试信息
	fmt.Printf("%s Fofa API Response: %s\n", config.ColorBlue("[DEBUG]"), string(bodyBytes))

	// 重新创建响应体
	resp.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))

	// 解析总数响应
	var totalResponse struct {
		Error   bool       `json:"error"`
		Size    int        `json:"size"`
		Page    int        `json:"page"`
		Mode    string     `json:"mode"`
		Query   string     `json:"query"`
		Results [][]string `json:"results"`
		Errmsg  string     `json:"errmsg"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&totalResponse); err != nil {
		return nil, fmt.Errorf("failed to decode Fofa response: %w", err)
	}

	if totalResponse.Error {
		return nil, fmt.Errorf("Fofa API returned error: %s", totalResponse.Errmsg)
	}

	// 显示总数信息
	totalCount := totalResponse.Size
	fmt.Printf("%s Fofa平台总数据量: %d 条\n", config.ColorCyan("[INFO]"), totalCount)

	// 如果用户没有确认继续，询问是否继续
	if !confirmContinue {
		fmt.Printf("%s 是否继续爬取Fofa数据？(y/n): ", config.ColorYellow("[CONFIRM]"))
		var input string
		fmt.Scanln(&input)
		if input != "y" && input != "Y" && input != "yes" && input != "YES" {
			fmt.Printf("%s 跳过Fofa数据爬取\n", config.ColorYellow("[SKIP]"))
			return []AssetInfo{}, nil
		}
	}

	// Fofa API每页最大限制
	maxPageSize := 10000
	pageSize := min(ac.Count, maxPageSize)

	// 计算总页数
	totalPages := (totalCount + pageSize - 1) / pageSize // 向上取整

	// 如果数据量超过100，需要分页
	pagesToFetch := 1
	if totalCount > 100 {
		// 询问用户想要爬取多少页
		if !confirmContinue {
			fmt.Printf("%s 指定爬取的页数：(1-%d，输入0表示全部): ", config.ColorYellow("[CONFIRM]"), totalPages)
			var pagesInput string
			fmt.Scanln(&pagesInput)
			if pagesInput != "" {
				if pages, err := strconv.Atoi(pagesInput); err == nil && pages >= 0 {
					if pages == 0 {
						pagesToFetch = totalPages
					} else {
						pagesToFetch = min(pages, totalPages)
					}
				}
			} else {
				pagesToFetch = totalPages
			}
		} else {
			// 如果使用了-all yes，默认爬取所有页
			pagesToFetch = totalPages
		}
	} else {
		// 数据量不超过100，只爬取1页
		pagesToFetch = 1
	}

	// 转换数据格式
	var assets []AssetInfo

	// 循环爬取多页数据
	for page := 1; page <= pagesToFetch; page++ {
		// 构建实际API URL
		apiURL := fmt.Sprintf("https://fofa.info/api/v1/search/all?email=%s&key=%s&qbase64=%s&page=%d&size=%d&fields=host,ip,port,protocol,title,icp",
			url.QueryEscape(ac.FofaEmail),
			url.QueryEscape(ac.FofaKey),
			url.QueryEscape(queryBase64),
			page,
			pageSize)

		// 发送请求
		resp, err := ac.client.Get(apiURL)
		if err != nil {
			fmt.Printf("%s 第%d页请求失败: %v\n", config.ColorRed("[ERROR]"), page, err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			// 读取响应体以获取更多错误信息
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			fmt.Printf("%s 第%d页请求失败，状态码: %d, 响应: %s\n", config.ColorRed("[ERROR]"), page, resp.StatusCode, string(bodyBytes))
			continue
		}

		// 读取响应体用于调试
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			resp.Body.Close()
			fmt.Printf("%s 第%d页读取响应失败: %v\n", config.ColorRed("[ERROR]"), page, err)
			continue
		}

		// 打印调试信息
		fmt.Printf("%s Fofa API Response: %s\n", config.ColorBlue("[DEBUG]"), string(bodyBytes))

		// 重新创建响应体
		resp.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))

		// 解析响应
		var fofaResponse struct {
			Error   bool       `json:"error"`
			Size    int        `json:"size"`
			Page    int        `json:"page"`
			Mode    string     `json:"mode"`
			Query   string     `json:"query"`
			Results [][]string `json:"results"`
			Errmsg  string     `json:"errmsg"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&fofaResponse); err != nil {
			resp.Body.Close()
			fmt.Printf("%s 第%d页解析失败: %v\n", config.ColorRed("[ERROR]"), page, err)
			continue
		}
		resp.Body.Close()

		if fofaResponse.Error {
			fmt.Printf("%s 第%d页API返回错误: %s\n", config.ColorRed("[ERROR]"), page, fofaResponse.Errmsg)
			continue
		}

		fmt.Printf("%s 正在爬取第%d页，获取到%d条数据\n", config.ColorBlue("[INFO]"), page, len(fofaResponse.Results))

		// 转换数据格式
		for _, result := range fofaResponse.Results {
			if len(result) >= 6 {
				// 创建原始数据映射
				rawData := map[string]interface{}{
					"host":     result[0],
					"ip":       result[1],
					"port":     result[2],
					"protocol": result[3],
					"title":    result[4],
					"icp":      result[5],
				}

				asset := AssetInfo{
					URL:          result[0],
					IP:           result[1],
					Port:         result[2],
					Protocol:     result[3],
					Title:        result[4],
					ICPNumber:    result[5],
					ResponseCode: 200,       // Fofa默认响应码
					Product:      result[3], // 使用协议作为产品
					Service:      result[3], // 使用协议作为服务
					Path:         "/",       // 默认路径
					Location:     "未知",      // 默认位置
					UpdateTime:   time.Now().Format("2006-01-02 15:04:05"),
					ASN:          "未知", // 默认ASN
					Operator:     "未知", // 默认运营商
					// Fofa特有字段
					Host: result[0], // 主机名
					// 原始数据
					RawData: rawData,
				}
				assets = append(assets, asset)
			}
		}
	}

	return assets, nil
}

// collectQuakeData 收集360 Quake数据
func (ac *AssetCollector) collectQuakeData() ([]AssetInfo, error) {
	return ac.collectQuakeDataWithPagination(false)
}

// collectQuakeDataWithPagination 收集360 Quake数据（支持分页）
func (ac *AssetCollector) collectQuakeDataWithPagination(confirmContinue bool) ([]AssetInfo, error) {
	// 先获取总数信息
	totalAPIURL := "https://quake.360.net/api/v3/search/quake_service"

	// 构建请求体 - JSON格式
	totalRequestBody := map[string]interface{}{
		"query":        ac.Query,
		"start":        0,
		"size":         1, // 只获取1条来获取总数
		"ignore_cache": false,
		"latest":       true,
	}

	// 将请求体转换为JSON
	jsonData, err := json.Marshal(totalRequestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Quake request: %w", err)
	}

	// 发送请求
	req, err := http.NewRequest("POST", totalAPIURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create Quake request: %w", err)
	}

	// 添加认证头 - 使用X-QuakeToken方式
	req.Header.Set("X-QuakeToken", ac.QuakeKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := ac.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request Quake API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// 读取响应体以获取更多错误信息
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Quake API returned status code: %d, response: %s", resp.StatusCode, string(bodyBytes))
	}

	// 读取响应体用于调试
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// 打印调试信息
	fmt.Printf("%s Quake API Response: %s\n", config.ColorBlue("[DEBUG]"), string(bodyBytes))

	// 重新创建响应体
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// 解析响应
	var totalResponse struct {
		Code interface{} `json:"code"` // 可能是int或string
		Meta struct {
			Pagination struct {
				Count     int `json:"count"`
				PageIndex int `json:"page_index"`
				PageSize  int `json:"page_size"`
				Total     int `json:"total"`
			} `json:"pagination"`
		} `json:"meta"`
		Data    interface{} `json:"data"` // 可能是数组或对象
		Message string      `json:"message"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&totalResponse); err != nil {
		return nil, fmt.Errorf("failed to decode Quake response: %w", err)
	}

	// 检查code字段
	var code int
	var isError bool
	switch v := totalResponse.Code.(type) {
	case int:
		code = v
		isError = code != 0
	case float64:
		code = int(v)
		isError = code != 0
	case string:
		// 如果是字符串，检查是否是错误码
		if v == "0" || v == "success" {
			code = 0
			isError = false
		} else {
			return nil, fmt.Errorf("Quake API returned error code: %s, message: %s", v, totalResponse.Message)
		}
	default:
		return nil, fmt.Errorf("Quake API returned unexpected code type: %T", totalResponse.Code)
	}

	if isError {
		return nil, fmt.Errorf("Quake API returned error code: %d, message: %s", code, totalResponse.Message)
	}

	// 显示总数信息
	totalCount := totalResponse.Meta.Pagination.Total
	fmt.Printf("%s 360 Quake平台总数据量: %d 条\n", config.ColorCyan("[INFO]"), totalCount)

	// 如果用户没有确认继续，询问是否继续
	if !confirmContinue {
		fmt.Printf("%s 是否继续爬取360 Quake数据？(y/n): ", config.ColorYellow("[CONFIRM]"))
		var input string
		fmt.Scanln(&input)
		if input != "y" && input != "Y" && input != "yes" && input != "YES" {
			fmt.Printf("%s 跳过360 Quake数据爬取\n", config.ColorYellow("[SKIP]"))
			return []AssetInfo{}, nil
		}
	}

	// 360 Quake API每页最大限制
	maxPageSize := 100
	pageSize := min(ac.Count, maxPageSize)

	// 计算总页数
	totalPages := (totalCount + pageSize - 1) / pageSize // 向上取整

	// 如果数据量超过100，需要分页
	pagesToFetch := 1
	if totalCount > 100 {
		// 询问用户想要爬取多少页
		if !confirmContinue {
			fmt.Printf("%s 指定爬取的页数：(1-%d，输入0表示全部): ", config.ColorYellow("[CONFIRM]"), totalPages)
			var pagesInput string
			fmt.Scanln(&pagesInput)
			if pagesInput != "" {
				if pages, err := strconv.Atoi(pagesInput); err == nil && pages >= 0 {
					if pages == 0 {
						pagesToFetch = totalPages
					} else {
						pagesToFetch = min(pages, totalPages)
					}
				}
			} else {
				pagesToFetch = totalPages
			}
		} else {
			// 如果使用了-all yes，默认爬取所有页
			pagesToFetch = totalPages
		}
	} else {
		// 数据量不超过100，只爬取1页
		pagesToFetch = 1
	}

	// 转换数据格式
	var assets []AssetInfo

	// 循环爬取多页数据
	for page := 1; page <= pagesToFetch; page++ {
		// 构建实际API URL
		apiURL := "https://quake.360.net/api/v3/search/quake_service"

		// 构建请求体 - Quake使用start参数，start从0开始
		start := (page - 1) * pageSize
		requestBody := map[string]interface{}{
			"query":        ac.Query,
			"start":        start,
			"size":         pageSize,
			"ignore_cache": false,
			"latest":       true,
		}

		// 将请求体转换为JSON
		jsonData, err := json.Marshal(requestBody)
		if err != nil {
			fmt.Printf("%s 第%d页请求体序列化失败: %v\n", config.ColorRed("[ERROR]"), page, err)
			continue
		}

		// 发送请求
		req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
		if err != nil {
			fmt.Printf("%s 第%d页创建请求失败: %v\n", config.ColorRed("[ERROR]"), page, err)
			continue
		}

		// 添加认证头 - 使用X-QuakeToken方式
		req.Header.Set("X-QuakeToken", ac.QuakeKey)
		req.Header.Set("Content-Type", "application/json")

		resp, err := ac.client.Do(req)
		if err != nil {
			fmt.Printf("%s 第%d页请求失败: %v\n", config.ColorRed("[ERROR]"), page, err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			// 读取响应体以获取更多错误信息
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			fmt.Printf("%s 第%d页请求失败，状态码: %d, 响应: %s\n", config.ColorRed("[ERROR]"), page, resp.StatusCode, string(bodyBytes))
			continue
		}

		// 读取响应体用于调试
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			resp.Body.Close()
			fmt.Printf("%s 第%d页读取响应失败: %v\n", config.ColorRed("[ERROR]"), page, err)
			continue
		}

		// 打印调试信息
		fmt.Printf("%s Quake API Response: %s\n", config.ColorBlue("[DEBUG]"), string(bodyBytes))

		// 重新创建响应体
		resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		// 解析响应
		var quakeResponse struct {
			Code    interface{} `json:"code"` // 可能是int或string
			Meta    interface{} `json:"meta"` // 可能是对象或空
			Data    interface{} `json:"data"` // 可能是数组或对象
			Message string      `json:"message"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&quakeResponse); err != nil {
			resp.Body.Close()
			fmt.Printf("%s 第%d页解析失败: %v\n", config.ColorRed("[ERROR]"), page, err)
			continue
		}
		resp.Body.Close()

		// 检查code字段
		var code int
		var isError bool
		switch v := quakeResponse.Code.(type) {
		case int:
			code = v
			isError = code != 0
		case float64:
			code = int(v)
			isError = code != 0
		case string:
			// 如果是字符串，检查是否是错误码
			if v == "0" || v == "success" {
				code = 0
				isError = false
			} else {
				fmt.Printf("%s 第%d页API返回错误: code=%s, message=%s\n", config.ColorRed("[ERROR]"), page, v, quakeResponse.Message)
				continue
			}
		default:
			fmt.Printf("%s 第%d页API返回意外的code类型: %T\n", config.ColorRed("[ERROR]"), page, quakeResponse.Code)
			continue
		}

		if isError {
			fmt.Printf("%s 第%d页API返回错误: code=%d, message=%s\n", config.ColorRed("[ERROR]"), page, code, quakeResponse.Message)
			continue
		}

		// 检查data字段类型
		dataSlice, ok := quakeResponse.Data.([]interface{})
		if !ok {
			// 如果data不是数组，可能是空数据或错误响应
			if quakeResponse.Data == nil {
				fmt.Printf("%s 第%d页API返回空数据\n", config.ColorYellow("[WARNING]"), page)
				continue
			}
			fmt.Printf("%s 第%d页API返回意外的数据格式: %T, message: %s\n", config.ColorRed("[ERROR]"), page, quakeResponse.Data, quakeResponse.Message)
			continue
		}

		fmt.Printf("%s 正在爬取第%d页，获取到%d条数据\n", config.ColorBlue("[INFO]"), page, len(dataSlice))

		// 转换数据格式
		for _, item := range dataSlice {
			itemMap, ok := item.(map[string]interface{})
			if !ok {
				continue
			}

			// 提取字段
			ip, _ := itemMap["ip"].(string)
			portFloat, _ := itemMap["port"].(float64)
			port := strconv.Itoa(int(portFloat))

			// 提取service信息
			serviceMap, _ := itemMap["service"].(map[string]interface{})
			serviceName, _ := serviceMap["name"].(string)

			// 提取HTTP信息
			httpMap, _ := serviceMap["http"].(map[string]interface{})
			host, _ := httpMap["host"].(string)
			title, _ := httpMap["title"].(string)

			// 提取ICP信息
			icpMap, _ := itemMap["icp"].(map[string]interface{})
			icpNumber, _ := icpMap["number"].(string)

			// 保存所有原始数据
			rawData := make(map[string]interface{})
			for key, value := range itemMap {
				rawData[key] = value
			}

			asset := AssetInfo{
				URL:          host,
				IP:           ip,
				Port:         port,
				Protocol:     serviceName,
				Title:        title,
				ICPNumber:    icpNumber,
				ResponseCode: 200,         // Quake默认响应码
				Product:      serviceName, // 使用服务名作为产品
				Service:      serviceName, // 使用服务名作为服务
				Path:         "/",         // 默认路径
				Location:     "未知",        // 默认位置
				UpdateTime:   time.Now().Format("2006-01-02 15:04:05"),
				ASN:          "未知", // 默认ASN
				Operator:     "未知", // 默认运营商
				// 360 Quake特有字段
				Domain:         host,        // 域名
				OS:             "未知",        // 操作系统
				Country:        "未知",        // 国家
				Province:       "未知",        // 省份
				City:           "未知",        // 城市
				Company:        "未知",        // 公司
				IsWeb:          "未知",        // 是否Web资产
				IsRisk:         "未知",        // 是否风险
				IsRiskProtocol: "未知",        // 是否风险协议
				ASOrg:          "未知",        // AS组织
				ISP:            "未知",        // ISP
				Banner:         "未知",        // Banner
				Header:         "未知",        // Header
				BaseProtocol:   serviceName, // 基础协议
				// 原始数据
				RawData: rawData,
			}
			assets = append(assets, asset)
		}
	}

	return assets, nil
}

// collectHunterData 收集Hunter数据
func (ac *AssetCollector) collectHunterData() ([]AssetInfo, error) {
	return ac.collectHunterDataWithPagination(false)
}

// collectHunterDataWithPagination 收集Hunter数据（支持分页）
func (ac *AssetCollector) collectHunterDataWithPagination(confirmContinue bool) ([]AssetInfo, error) {
	// Base64 URL编码查询语句 - Hunter API使用base64.URLEncoding
	queryBase64 := base64.URLEncoding.EncodeToString([]byte(ac.Query))

	// 先获取总数信息
	totalAPIURL := fmt.Sprintf("https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=1&page_size=1",
		url.QueryEscape(ac.HunterKey),
		url.QueryEscape(queryBase64))

	// 发送请求
	resp, err := ac.client.Get(totalAPIURL)
	if err != nil {
		return nil, fmt.Errorf("failed to request Hunter API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// 读取响应体以获取更多错误信息
		bodyBytes, _ := io.ReadAll(resp.Body)
		fmt.Printf("%s Hunter API Error Response: %s\n", config.ColorRed("[DEBUG]"), string(bodyBytes))
		return nil, fmt.Errorf("Hunter API returned status code: %d, response: %s", resp.StatusCode, string(bodyBytes))
	}

	// 解析总数响应 - 根据Hunter API文档更新结构
	var totalResponse struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Total int `json:"total"`
			Time  int `json:"time"`
			Arr   []struct {
				WebTitle       string `json:"web_title"`
				IP             string `json:"ip"`
				Port           int    `json:"port"`
				BaseProtocol   string `json:"base_protocol"`
				Protocol       string `json:"protocol"`
				Domain         string `json:"domain"`
				URL            string `json:"url"`
				OS             string `json:"os"`
				Country        string `json:"country"`
				Province       string `json:"province"`
				City           string `json:"city"`
				UpdatedAt      string `json:"updated_at"`
				StatusCode     int    `json:"status_code"`
				Number         string `json:"number"`
				Company        string `json:"company"`
				IsWeb          string `json:"is_web"`
				IsRisk         string `json:"is_risk"`
				IsRiskProtocol string `json:"is_risk_protocol"`
				ASOrg          string `json:"as_org"`
				ISP            string `json:"isp"`
				Banner         string `json:"banner"`
				Header         string `json:"header"`
			} `json:"arr"`
			ConsumeQuota string `json:"consume_quota"`
			RestQuota    string `json:"rest_quota"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&totalResponse); err != nil {
		return nil, fmt.Errorf("failed to decode Hunter response: %w", err)
	}

	if totalResponse.Code != 200 {
		return nil, fmt.Errorf("Hunter API returned error code: %d, message: %s", totalResponse.Code, totalResponse.Message)
	}

	// 显示总数信息
	totalCount := totalResponse.Data.Total
	fmt.Printf("%s Hunter平台总数据量: %d 条\n", config.ColorCyan("[INFO]"), totalCount)

	// 如果用户没有确认继续，询问是否继续
	if !confirmContinue {
		fmt.Printf("%s 是否继续爬取Hunter数据？(y/n): ", config.ColorYellow("[CONFIRM]"))
		var input string
		fmt.Scanln(&input)
		if input != "y" && input != "Y" && input != "yes" && input != "YES" {
			fmt.Printf("%s 跳过Hunter数据爬取\n", config.ColorYellow("[SKIP]"))
			return []AssetInfo{}, nil
		}
	}

	// Hunter API每页最大限制
	maxPageSize := 100
	pageSize := min(ac.Count, maxPageSize)

	// 计算总页数
	totalPages := (totalCount + pageSize - 1) / pageSize // 向上取整

	// 如果数据量超过100，需要分页
	pagesToFetch := 1
	if totalCount > 100 {
		// 询问用户想要爬取多少页
		if !confirmContinue {
			fmt.Printf("%s 指定爬取的页数：(1-%d，输入0表示全部): ", config.ColorYellow("[CONFIRM]"), totalPages)
			var pagesInput string
			fmt.Scanln(&pagesInput)
			if pagesInput != "" {
				if pages, err := strconv.Atoi(pagesInput); err == nil && pages >= 0 {
					if pages == 0 {
						pagesToFetch = totalPages
					} else {
						pagesToFetch = min(pages, totalPages)
					}
				}
			} else {
				pagesToFetch = totalPages
			}
		} else {
			// 如果使用了-all yes，默认爬取所有页
			pagesToFetch = totalPages
		}
	} else {
		// 数据量不超过100，只爬取1页
		pagesToFetch = 1
	}

	// 转换数据格式 - 使用Hunter API文档中的字段
	var assets []AssetInfo

	// 循环爬取多页数据
	for page := 1; page <= pagesToFetch; page++ {
		// 构建API URL - Hunter API使用不同的参数格式
		apiURL := fmt.Sprintf("https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=%d&page_size=%d",
			url.QueryEscape(ac.HunterKey),
			url.QueryEscape(queryBase64),
			page,
			pageSize)

		// 发送请求
		resp, err := ac.client.Get(apiURL)
		if err != nil {
			fmt.Printf("%s 第%d页请求失败: %v\n", config.ColorRed("[ERROR]"), page, err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			// 读取响应体以获取更多错误信息
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			fmt.Printf("%s 第%d页请求失败，状态码: %d, 响应: %s\n", config.ColorRed("[ERROR]"), page, resp.StatusCode, string(bodyBytes))
			continue
		}

		// 解析响应 - 根据Hunter API文档更新结构
		var hunterResponse struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Data    struct {
				Total int `json:"total"`
				Time  int `json:"time"`
				Arr   []struct {
					WebTitle       string `json:"web_title"`
					IP             string `json:"ip"`
					Port           int    `json:"port"`
					BaseProtocol   string `json:"base_protocol"`
					Protocol       string `json:"protocol"`
					Domain         string `json:"domain"`
					URL            string `json:"url"`
					OS             string `json:"os"`
					Country        string `json:"country"`
					Province       string `json:"province"`
					City           string `json:"city"`
					UpdatedAt      string `json:"updated_at"`
					StatusCode     int    `json:"status_code"`
					Number         string `json:"number"`
					Company        string `json:"company"`
					IsWeb          string `json:"is_web"`
					IsRisk         string `json:"is_risk"`
					IsRiskProtocol string `json:"is_risk_protocol"`
					ASOrg          string `json:"as_org"`
					ISP            string `json:"isp"`
					Banner         string `json:"banner"`
					Header         string `json:"header"`
				} `json:"arr"`
				ConsumeQuota string `json:"consume_quota"`
				RestQuota    string `json:"rest_quota"`
			} `json:"data"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&hunterResponse); err != nil {
			resp.Body.Close()
			fmt.Printf("%s 第%d页解析失败: %v\n", config.ColorRed("[ERROR]"), page, err)
			continue
		}
		resp.Body.Close()

		if hunterResponse.Code != 200 {
			fmt.Printf("%s 第%d页API返回错误: code=%d, message=%s\n", config.ColorRed("[ERROR]"), page, hunterResponse.Code, hunterResponse.Message)
			continue
		}

		fmt.Printf("%s 正在爬取第%d页，获取到%d条数据\n", config.ColorBlue("[INFO]"), page, len(hunterResponse.Data.Arr))

		// 转换数据格式
		for _, item := range hunterResponse.Data.Arr {
			// 创建原始数据映射
			rawData := map[string]interface{}{
				"url":              item.URL,
				"ip":               item.IP,
				"port":             item.Port,
				"protocol":         item.Protocol,
				"web_title":        item.WebTitle,
				"number":           item.Number,
				"status_code":      item.StatusCode,
				"base_protocol":    item.BaseProtocol,
				"domain":           item.Domain,
				"os":               item.OS,
				"country":          item.Country,
				"province":         item.Province,
				"city":             item.City,
				"company":          item.Company,
				"is_web":           item.IsWeb,
				"is_risk":          item.IsRisk,
				"is_risk_protocol": item.IsRiskProtocol,
				"as_org":           item.ASOrg,
				"isp":              item.ISP,
				"banner":           item.Banner,
				"header":           item.Header,
				"updated_at":       item.UpdatedAt,
			}

			asset := AssetInfo{
				URL:          item.URL,
				IP:           item.IP,
				Port:         strconv.Itoa(item.Port),
				Protocol:     item.Protocol,
				Title:        item.WebTitle,
				ICPNumber:    item.Number,
				ResponseCode: item.StatusCode,
				Product:      item.BaseProtocol, // 使用基础协议作为产品
				Service:      item.Protocol,     // 使用协议作为服务
				Path:         "/",               // 默认路径
				Location:     fmt.Sprintf("%s %s %s", item.Country, item.Province, item.City),
				UpdateTime:   item.UpdatedAt,
				ASN:          item.ASOrg, // 使用AS组织
				Operator:     item.ISP,   // 使用ISP信息
				// Hunter特有字段
				WebTitle:     item.WebTitle,                    // Web标题
				Number:       item.Number,                      // 编号
				ConsumeQuota: hunterResponse.Data.ConsumeQuota, // 消耗积分
				RestQuota:    hunterResponse.Data.RestQuota,    // 剩余积分
				// 360 Quake字段（Hunter也有）
				Domain:         item.Domain,         // 域名
				OS:             item.OS,             // 操作系统
				Country:        item.Country,        // 国家
				Province:       item.Province,       // 省份
				City:           item.City,           // 城市
				Company:        item.Company,        // 公司
				IsWeb:          item.IsWeb,          // 是否Web资产
				IsRisk:         item.IsRisk,         // 是否风险
				IsRiskProtocol: item.IsRiskProtocol, // 是否风险协议
				ASOrg:          item.ASOrg,          // AS组织
				ISP:            item.ISP,            // ISP
				Banner:         item.Banner,         // Banner
				Header:         item.Header,         // Header
				BaseProtocol:   item.BaseProtocol,   // 基础协议
				// 原始数据
				RawData: rawData,
			}
			assets = append(assets, asset)
		}
	}

	return assets, nil
}

// deduplicateAssets 去重处理
func (ac *AssetCollector) deduplicateAssets(assets []AssetInfo) []AssetInfo {
	seen := make(map[string]bool)
	var uniqueAssets []AssetInfo

	for _, asset := range assets {
		// 使用URL+IP+端口作为唯一标识
		key := fmt.Sprintf("%s:%s:%s", asset.URL, asset.IP, asset.Port)
		if !seen[key] {
			seen[key] = true
			uniqueAssets = append(uniqueAssets, asset)
		}
	}

	return uniqueAssets
}

// saveAssets 保存资产信息到文件
func (ac *AssetCollector) saveAssets(assets []AssetInfo) error {
	if len(assets) == 0 {
		fmt.Println(config.ColorYellow("[WARN]"), "No assets to save")
		return nil
	}

	// 创建输出目录
	outputDir := "output/assets"
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// 生成文件名
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("assets_%s.csv", timestamp)
	filepath := filepath.Join(outputDir, filename)

	// 创建CSV文件
	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// 写入BOM头（支持中文）
	file.WriteString("\xEF\xBB\xBF")

	// 创建CSV写入器
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 收集所有可能的字段名
	allFields := make(map[string]bool)
	for _, asset := range assets {
		// 添加基础字段
		allFields["序号"] = true
		allFields["URL"] = true
		allFields["IP"] = true
		allFields["端口"] = true
		allFields["协议"] = true
		allFields["网站标题"] = true
		allFields["ICP备案号"] = true
		allFields["数据来源"] = true
		allFields["响应码"] = true
		allFields["产品应用"] = true
		allFields["网站服务"] = true
		allFields["网站路径"] = true
		allFields["地理位置"] = true
		allFields["更新时间"] = true
		allFields["ASN"] = true
		allFields["运营商"] = true

		// 添加原始数据字段
		for key := range asset.RawData {
			allFields[key] = true
		}
	}

	// 生成字段列表
	var headers []string
	for field := range allFields {
		headers = append(headers, field)
	}
	sort.Strings(headers)

	// 写入表头
	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("failed to write headers: %w", err)
	}

	// 写入数据
	for _, asset := range assets {
		record := make([]string, len(headers))

		// 填充基础字段
		for i, header := range headers {
			switch header {
			case "序号":
				record[i] = strconv.Itoa(asset.Index)
			case "URL":
				record[i] = asset.URL
			case "IP":
				record[i] = asset.IP
			case "端口":
				record[i] = asset.Port
			case "协议":
				record[i] = asset.Protocol
			case "网站标题":
				record[i] = asset.Title
			case "ICP备案号":
				record[i] = asset.ICPNumber
			case "数据来源":
				record[i] = asset.Source
			case "响应码":
				record[i] = strconv.Itoa(asset.ResponseCode)
			case "产品应用":
				record[i] = asset.Product
			case "网站服务":
				record[i] = asset.Service
			case "网站路径":
				record[i] = asset.Path
			case "地理位置":
				record[i] = asset.Location
			case "更新时间":
				record[i] = asset.UpdateTime
			case "ASN":
				record[i] = asset.ASN
			case "运营商":
				record[i] = asset.Operator
			default:
				// 从原始数据中获取
				if value, exists := asset.RawData[header]; exists {
					record[i] = fmt.Sprintf("%v", value)
				} else {
					record[i] = ""
				}
			}
		}

		if err := writer.Write(record); err != nil {
			return fmt.Errorf("failed to write record: %w", err)
		}
	}

	fmt.Printf("%s Assets saved to: %s\n", config.ColorGreen("[SUCCESS]"), filepath)
	return nil
}

// PrintAssetSummary 打印资产汇总信息
func (ac *AssetCollector) PrintAssetSummary(assets []AssetInfo) {
	if len(assets) == 0 {
		fmt.Println(config.ColorYellow("[SUMMARY]"), "No assets found")
		return
	}

	// 统计各平台数据
	fofaCount := 0
	quakeCount := 0
	hunterCount := 0

	for _, asset := range assets {
		switch asset.Source {
		case "Fofa":
			fofaCount++
		case "360 Quake":
			quakeCount++
		case "Hunter":
			hunterCount++
		}
	}

	fmt.Println(config.ColorCyan("[SUMMARY]"), "Asset Collection Summary:")
	fmt.Printf("  Total Assets: %d\n", len(assets))
	fmt.Printf("  Fofa: %d\n", fofaCount)
	fmt.Printf("  360 Quake: %d\n", quakeCount)
	fmt.Printf("  Hunter: %d\n", hunterCount)
}

// generateAssetScanReport 按照资产扫描格式生成HTML报告
func (ac *AssetCollector) generateAssetScanReport(uniqueAssets []AssetInfo, fofaAssets, quakeAssets, hunterAssets []AssetInfo) error {
	// 创建输出目录
	outputDir := "output/assets"
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// 生成文件名（按照资产扫描的格式）
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("eaglesword_asset_%s.html", timestamp)
	filepath := filepath.Join(outputDir, filename)

	// 生成HTML内容
	htmlContent := ac.generateAssetScanHTMLContent(uniqueAssets, fofaAssets, quakeAssets, hunterAssets)

	// 写入文件
	if err := os.WriteFile(filepath, []byte(htmlContent), 0644); err != nil {
		return fmt.Errorf("failed to write HTML file: %w", err)
	}

	fmt.Printf("%s Asset scan report generated: %s\n", config.ColorGreen("[SUCCESS]"), filepath)
	return nil
}

// generateDynamicTable 动态生成表格HTML
func (ac *AssetCollector) generateDynamicTable(assets []AssetInfo, tableID string) string {
	if len(assets) == 0 {
		return "<p>暂无数据</p>"
	}

	// 收集所有可能的字段名
	allFields := make(map[string]bool)
	for _, asset := range assets {
		// 添加基础字段
		allFields["序号"] = true
		allFields["URL"] = true
		allFields["IP"] = true
		allFields["端口"] = true
		allFields["协议"] = true
		allFields["网站标题"] = true
		allFields["ICP备案号"] = true
		allFields["数据来源"] = true
		allFields["响应码"] = true
		allFields["产品应用"] = true
		allFields["网站服务"] = true
		allFields["网站路径"] = true
		allFields["地理位置"] = true
		allFields["更新时间"] = true
		allFields["ASN"] = true
		allFields["运营商"] = true

		// 添加原始数据字段
		for key := range asset.RawData {
			allFields[key] = true
		}
	}

	// 生成字段列表
	var headers []string
	for field := range allFields {
		headers = append(headers, field)
	}
	sort.Strings(headers)

	// 生成表头
	html := fmt.Sprintf(`
                <div class="table-container">
                    <table class="data-table" id="%s">
                        <thead>
                            <tr>`, tableID)

	for _, header := range headers {
		html += fmt.Sprintf(`
                                <th>%s</th>`, htmlpkg.EscapeString(header))
	}

	html += `
                            </tr>
                        </thead>
                        <tbody>`

	// 生成数据行
	for _, asset := range assets {
		html += `
                            <tr>`

		for _, header := range headers {
			var value string
			switch header {
			case "序号":
				value = strconv.Itoa(asset.Index)
			case "URL":
				value = asset.URL
			case "IP":
				value = asset.IP
			case "端口":
				value = asset.Port
			case "协议":
				value = asset.Protocol
			case "网站标题":
				value = asset.Title
			case "ICP备案号":
				value = asset.ICPNumber
			case "数据来源":
				value = asset.Source
			case "响应码":
				value = strconv.Itoa(asset.ResponseCode)
			case "产品应用":
				value = asset.Product
			case "网站服务":
				value = asset.Service
			case "网站路径":
				value = asset.Path
			case "地理位置":
				value = asset.Location
			case "更新时间":
				value = asset.UpdateTime
			case "ASN":
				value = asset.ASN
			case "运营商":
				value = asset.Operator
			default:
				// 从原始数据中获取
				if val, exists := asset.RawData[header]; exists {
					value = fmt.Sprintf("%v", val)
				} else {
					value = ""
				}
			}

			// 如果是URL字段，添加链接
			if header == "URL" && value != "" {
				html += fmt.Sprintf(`
                                <td><a href="%s" target="_blank">%s</a></td>`,
					htmlpkg.EscapeString(value), htmlpkg.EscapeString(value))
			} else {
				html += fmt.Sprintf(`
                                <td>%s</td>`, htmlpkg.EscapeString(value))
			}
		}

		html += `
                            </tr>`
	}

	html += `
                        </tbody>
                    </table>
                </div>`

	return html
}

// generateAssetScanHTMLContent 生成资产扫描HTML内容
func (ac *AssetCollector) generateAssetScanHTMLContent(uniqueAssets []AssetInfo, fofaAssets, quakeAssets, hunterAssets []AssetInfo) string {
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	html := fmt.Sprintf(`<!DOCTYPE html>
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

        .query-info {
            background: #e3f2fd;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }

        .query-text {
            font-family: monospace;
            background: white;
            padding: 10px;
            border-radius: 3px;
            margin-top: 10px;
        }

        .platform-section {
            margin-bottom: 30px;
        }

        .platform-header {
            background: #e80030;
            color: white;
            padding: 12px 15px;
            font-weight: bold;
            font-size: 16px;
        }

        .platform-content {
            border: 1px solid #ddd;
            border-top: none;
        }

        .table-container {
            overflow-x: auto;
            border: 1px solid #ddd;
        }

        .data-table {
            width: 100%%;
            border-collapse: collapse;
            background: white;
            table-layout: auto;
        }

        .data-table th {
            background: #e80030;
            color: white;
            padding: 8px;
            text-align: left;
            font-weight: bold;
            font-size: 11px;
            white-space: nowrap;
            position: sticky;
            top: 0;
            z-index: 10;
        }

        .data-table td {
            padding: 8px;
            border-bottom: 1px solid #ddd;
            font-size: 11px;
            white-space: nowrap;
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .data-table tr:hover {
            background: #f8f9fa;
        }

        .data-table tr:last-child td {
            border-bottom: none;
        }

        .copy-all-btn {
            background: #ffc107;
            color: #333;
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            font-size: 12px;
            cursor: pointer;
            margin-bottom: 15px;
        }

        .copy-all-btn:hover {
            background: #e0a800;
        }

        .footer {
            background: white;
            padding: 20px;
            text-align: center;
            border: 1px solid #ddd;
            margin-top: 20px;
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

            .stats-grid {
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
        
        function copyAllFromTable(tableId) {
            const table = document.getElementById(tableId);
            if (!table) return;
            
            let allText = '';
            const rows = table.querySelectorAll('tbody tr');
            
            rows.forEach(function(row) {
                const urlCell = row.cells[1];
                if (urlCell) {
                    const url = urlCell.textContent.trim();
                    if (url) {
                        allText += url + '\n';
                    }
                }
            });
            
            navigator.clipboard.writeText(allText.trim()).then(function() {
                alert('已复制全部URL到剪贴板');
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
                    <div class="site-icon-placeholder">ES</div>
                    <div class="site-details">
                        <h1>EagleSword 资产收集报告</h1>
                        <span class="site-url">%s</span>
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
                        <span class="stat-number">%d</span>
                        <span class="stat-label">总资产数量</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-number">%d</span>
                        <span class="stat-label">Fofa 资产</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-number">%d</span>
                        <span class="stat-label">360 Quake 资产</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-number">%d</span>
                        <span class="stat-label">Hunter 资产</span>
                    </div>
                </div>
            </div>
        </header>

        <main>
            <div class="query-info">
                <h3>查询语句</h3>
                <div class="query-text">%s</div>
            </div>`, timestamp, timestamp, len(uniqueAssets), len(fofaAssets), len(quakeAssets), len(hunterAssets), htmlpkg.EscapeString(ac.Query))

	// 添加Fofa数据
	if len(fofaAssets) > 0 {
		html += fmt.Sprintf(`
            <div class="section platform-section">
                <h2>Fofa 数据 (%d 条)</h2>
                <button class="copy-all-btn" onclick="copyAllFromTable('fofa-table')">复制所有URL</button>
%s
            </div>`, len(fofaAssets), ac.generateDynamicTable(fofaAssets, "fofa-table"))
	}

	// 添加360 Quake数据
	if len(quakeAssets) > 0 {
		html += fmt.Sprintf(`
            <div class="section platform-section">
                <h2>360 Quake 数据 (%d 条)</h2>
                <button class="copy-all-btn" onclick="copyAllFromTable('quake-table')">复制所有URL</button>
%s
            </div>`, len(quakeAssets), ac.generateDynamicTable(quakeAssets, "quake-table"))
	}

	// 添加Hunter数据
	if len(hunterAssets) > 0 {
		html += fmt.Sprintf(`
            <div class="section platform-section">
                <h2>Hunter 数据 (%d 条)</h2>
                <button class="copy-all-btn" onclick="copyAllFromTable('hunter-table')">复制所有URL</button>
%s
            </div>`, len(hunterAssets), ac.generateDynamicTable(hunterAssets, "hunter-table"))
	}

	html += `
        </main>

        <footer class="footer">
            <p>Generated by EagleSword | Report time: ` + timestamp + `</p>
        </footer>
    </div>
</body>
</html>`

	return html
}
