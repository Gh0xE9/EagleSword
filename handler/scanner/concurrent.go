package scanner

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Gh0xE9/EagleSword/config"
)

// ConcurrentRequest 并发请求配置
type ConcurrentRequest struct {
	URL     string
	Method  string
	Headers map[string]string
	Cookies string
	Client  *http.Client
}

// ConcurrentResponse 并发请求响应
type ConcurrentResponse struct {
	URL        string
	StatusCode int
	Error      error
	Response   *http.Response
}

// ExecuteConcurrentRequests 执行并发请求，带超时和错误处理
func ExecuteConcurrentRequests(requests []ConcurrentRequest) []ConcurrentResponse {
	if len(requests) == 0 {
		return nil
	}

	// 限制并发数
	maxConcurrency := config.HTTPConfig.MaxConcurrency
	if len(requests) < maxConcurrency {
		maxConcurrency = len(requests)
	}

	// 创建信号量控制并发
	semaphore := make(chan struct{}, maxConcurrency)

	// 创建上下文，设置超时
	ctx, cancel := context.WithTimeout(context.Background(), config.HTTPConfig.Timeout*time.Duration(len(requests)))
	defer cancel()

	var wg sync.WaitGroup
	var mu sync.Mutex
	var responses []ConcurrentResponse

	for _, req := range requests {
		wg.Add(1)
		go func(request ConcurrentRequest) {
			defer wg.Done()

			// 获取信号量
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				mu.Lock()
				responses = append(responses, ConcurrentResponse{
					URL:   request.URL,
					Error: fmt.Errorf("context timeout: %w", ctx.Err()),
				})
				mu.Unlock()
				return
			}

			// 执行请求
			response := executeSingleRequest(ctx, request)

			// 线程安全地添加结果
			mu.Lock()
			responses = append(responses, response)
			mu.Unlock()
		}(req)
	}

	wg.Wait()
	return responses
}

// executeSingleRequest 执行单个请求
func executeSingleRequest(ctx context.Context, req ConcurrentRequest) ConcurrentResponse {
	// 创建请求
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, nil)
	if err != nil {
		return ConcurrentResponse{
			URL:   req.URL,
			Error: fmt.Errorf("failed to create request: %w", err),
		}
	}

	// 设置请求头
	for key, value := range req.Headers {
		httpReq.Header.Set(key, value)
	}

	// 设置Cookie
	if req.Cookies != "" {
		httpReq.Header.Set("Cookie", req.Cookies)
	}

	// 设置User-Agent
	httpReq.Header.Set("User-Agent", config.RandomUserAgent())

	// 执行请求
	resp, err := req.Client.Do(httpReq)
	if err != nil {
		return ConcurrentResponse{
			URL:   req.URL,
			Error: fmt.Errorf("request failed: %w", err),
		}
	}

	return ConcurrentResponse{
		URL:        req.URL,
		StatusCode: resp.StatusCode,
		Response:   resp,
		Error:      nil,
	}
}

// RetryRequest 带重试的请求执行
func RetryRequest(client *http.Client, url string, method string, headers map[string]string, cookies string) (*http.Response, error) {
	var lastErr error

	for i := 0; i <= config.HTTPConfig.RetryCount; i++ {
		// 创建请求
		req, err := http.NewRequest(method, url, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		// 设置请求头
		for key, value := range headers {
			req.Header.Set(key, value)
		}

		// 设置Cookie
		if cookies != "" {
			req.Header.Set("Cookie", cookies)
		}

		// 设置User-Agent
		req.Header.Set("User-Agent", config.RandomUserAgent())

		// 执行请求
		resp, err := client.Do(req)
		if err == nil {
			return resp, nil
		}

		lastErr = err

		// 如果不是最后一次重试，等待后重试
		if i < config.HTTPConfig.RetryCount {
			time.Sleep(config.HTTPConfig.RetryDelay)
		}
	}

	return nil, fmt.Errorf("request failed after %d retries: %w", config.HTTPConfig.RetryCount, lastErr)
}

// IsTimeoutError 检查是否是超时错误
func IsTimeoutError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	return containsAny(errStr, []string{
		"timeout",
		"deadline exceeded",
		"context deadline exceeded",
		"i/o timeout",
		"connection timed out",
	})
}

// IsNetworkError 检查是否是网络错误
func IsNetworkError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	return containsAny(errStr, []string{
		"connection refused",
		"no route to host",
		"network is unreachable",
		"connection reset",
		"broken pipe",
		"connection aborted",
	})
}

// containsAny 检查字符串是否包含任意一个子字符串
func containsAny(s string, substrings []string) bool {
	for _, substr := range substrings {
		if len(s) >= len(substr) {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
		}
	}
	return false
}
