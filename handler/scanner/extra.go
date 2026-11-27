package scanner

import (
	"fmt"
	"io"
	"net/http"

	"github.com/Gh0xE9/EagleSword/config"
)

// FetchText 执行简单 GET 并返回响应文本与状态码（使用 scanner 包的 UA 策略）
func FetchText(target string, proxyURL string) (string, int, error) {
	// 创建支持代理的Transport
	transport, err := createProxyTransport(proxyURL)
	if err != nil {
		return "", 0, fmt.Errorf("failed to create proxy transport: %w", err)
	}
	client := &http.Client{Transport: transport}

	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", config.RandomUserAgent())
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", resp.StatusCode, err
	}
	return string(b), resp.StatusCode, nil
}

// FetchBytes 执行简单 GET 并返回字节数据、状态码与 Content-Type（若无则为空）
func FetchBytes(target string, cookies string, headers map[string]string, proxyURL string) ([]byte, int, string, error) {
	// 创建支持代理的Transport
	transport, err := createProxyTransport(proxyURL)
	if err != nil {
		return nil, 0, "", fmt.Errorf("failed to create proxy transport: %w", err)
	}
	client := &http.Client{Transport: transport}

	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, 0, "", err
	}

	req.Header.Set("User-Agent", config.RandomUserAgent())

	if cookies != "" {
		req.Header.Set("Cookie", cookies)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, resp.Header.Get("Content-Type"), err
	}
	return b, resp.StatusCode, resp.Header.Get("Content-Type"), nil
}
