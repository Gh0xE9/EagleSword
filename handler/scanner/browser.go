package scanner

import (
	"context"
	"fmt"
	"strings"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/Gh0xE9/EagleSword/config"
)

// BrowserResult 浏览器渲染结果
type BrowserResult struct {
	HTML      string
	JSFiles   []string
	JSContent map[string]string // URL -> 内容
}

// RenderWithBrowser 使用 headless 浏览器渲染页面并获取所有 JS 文件
func RenderWithBrowser(targetURL string, headers map[string]string) (*BrowserResult, error) {
	// 创建浏览器上下文，添加忽略SSL证书错误的选项
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("ignore-ssl-errors", true),
		chromedp.Flag("ignore-certificate-errors-spki-list", true),
		chromedp.Flag("disable-web-security", true),
		chromedp.Flag("allow-running-insecure-content", true),
		chromedp.Flag("disable-features", "VizDisplayCompositor"),
		chromedp.Flag("disable-background-timer-throttling", true),
		chromedp.Flag("disable-backgrounding-occluded-windows", true),
		chromedp.Flag("disable-renderer-backgrounding", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-plugins", true),
		chromedp.Flag("disable-images", true),      // 禁用图片加载以提高速度
		chromedp.Flag("disable-javascript", false), // 保持JS启用
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-dev-shm-usage", true),
	)

	ctx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, cancel = chromedp.NewContext(ctx)
	defer cancel()

	// 设置超时 - 使用配置
	ctx, cancel = context.WithTimeout(ctx, config.BrowserConfig.Timeout)
	defer cancel()

	result := &BrowserResult{
		JSContent: make(map[string]string),
	}

	// 存储所有网络请求
	var requests []*network.EventRequestWillBeSent

	// 监听网络请求
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch ev := ev.(type) {
		case *network.EventRequestWillBeSent:
			requests = append(requests, ev)
		}
	})

	// 执行页面渲染
	err := chromedp.Run(ctx,
		// 启用网络域
		chromedp.ActionFunc(func(ctx context.Context) error {
			return network.Enable().Do(ctx)
		}),
		// 设置自定义请求头
		chromedp.ActionFunc(func(ctx context.Context) error {
			if len(headers) > 0 {
				networkHeaders := make(network.Headers)
				for k, v := range headers {
					networkHeaders[k] = v
				}
				return network.SetExtraHTTPHeaders(networkHeaders).Do(ctx)
			}
			return nil
		}),
		// 导航到目标页面
		chromedp.Navigate(targetURL),
		// 等待页面加载完成
		chromedp.WaitVisible("body", chromedp.ByQuery),
		// 等待更长时间让 JS 执行完成 - 使用配置
		chromedp.Sleep(config.BrowserConfig.WaitTime),
		// 获取页面 HTML
		chromedp.OuterHTML("html", &result.HTML),
	)

	if err != nil {
		// 检查是否是超时错误
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("浏览器渲染超时 (%v): %w", config.BrowserConfig.Timeout, err)
		}
		// 检查是否是网络错误
		if strings.Contains(err.Error(), "net::") {
			return nil, fmt.Errorf("网络连接失败: %w", err)
		}
		// 检查是否是SSL错误
		if strings.Contains(err.Error(), "certificate") || strings.Contains(err.Error(), "SSL") {
			return nil, fmt.Errorf("SSL证书错误: %w", err)
		}
		return nil, fmt.Errorf("浏览器渲染失败: %w", err)
	}

	// 从网络请求中提取 JS 文件
	for _, req := range requests {
		url := req.Request.URL
		// 检查是否是 JS 文件
		if isJSFile(url) {
			result.JSFiles = append(result.JSFiles, url)
		}
	}

	// 获取所有 JS 文件的内容
	for _, jsURL := range result.JSFiles {
		var content string
		err := chromedp.Run(ctx,
			chromedp.Navigate(jsURL),
			chromedp.OuterHTML("body", &content),
		)
		if err == nil {
			result.JSContent[jsURL] = content
		}
	}

	return result, nil
}

// isJSFile 检查 URL 是否是 JS 文件
func isJSFile(url string) bool {
	// 简单的检查：以 .js 结尾或包含 .js
	return len(url) > 3 && url[len(url)-3:] == ".js"
}
