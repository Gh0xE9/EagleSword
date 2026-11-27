package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"golang.org/x/net/proxy"
	"github.com/Gh0xE9/EagleSword/config"
)

type HTTPResult struct {
	Body      string
	Status    int
	UserAgent string
	Headers   map[string][]string
}

// createProxyTransport 创建支持代理的HTTP Transport
func createProxyTransport(proxyURL string) (*http.Transport, error) {
	// 创建基础Transport，跳过TLS证书验证
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	if proxyURL == "" {
		return transport, nil
	}

	// 解析代理URL
	parsedProxyURL, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	// 根据代理类型配置Transport
	switch parsedProxyURL.Scheme {
	case "http", "https":
		transport.Proxy = http.ProxyURL(parsedProxyURL)
	case "socks5":
		// 创建SOCKS5代理dialer
		password, _ := parsedProxyURL.User.Password()
		auth := &proxy.Auth{
			User:     parsedProxyURL.User.Username(),
			Password: password,
		}
		dialer, err := proxy.SOCKS5("tcp", parsedProxyURL.Host, auth, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("failed to create SOCKS5 proxy: %w", err)
		}
		transport.Dial = dialer.Dial
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s (supported: http, https, socks5)", parsedProxyURL.Scheme)
	}

	return transport, nil
}

func WebFetch(target string, cookies string, headers map[string]string, proxyURL string) (HTTPResult, error) {
	// 创建支持代理的Transport
	transport, err := createProxyTransport(proxyURL)
	if err != nil {
		return HTTPResult{}, fmt.Errorf("failed to create proxy transport: %w", err)
	}
	client := &http.Client{Transport: transport}

	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return HTTPResult{}, err
	}

	userAgent := config.RandomUserAgent()
	req.Header.Set("User-Agent", userAgent)

	if cookies != "" {
		req.Header.Set("Cookie", cookies)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return HTTPResult{}, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return HTTPResult{Status: resp.StatusCode, UserAgent: userAgent}, err
	}
	return HTTPResult{Body: string(b), Status: resp.StatusCode, UserAgent: userAgent, Headers: resp.Header}, nil
}
