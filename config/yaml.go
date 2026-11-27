package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type YamlConfig struct {
	EagleSword struct {
		Timeout int    `yaml:"timeout"`
		Cookie  string `yaml:"cookie"`
	} `yaml:"eaglesword"`

	APIKey struct {
		Quake     string `yaml:"quake"`
		Hunter    string `yaml:"hunter"`
		Shodan    string `yaml:"shodan"`
		Fofa      string `yaml:"fofa"`
		FofaEmail string `yaml:"fofa_email"`
	} `yaml:"api_key"`

	Notify struct {
		Feishu string `yaml:"feishu"`
	} `yaml:"notify"`

	Risk struct {
		APIReponseLength int `yaml:"api_response_length"`
		APITitleLength   int `yaml:"api_title_length"`
	} `yaml:"risk"`

	Dictionary struct {
		Path            string `yaml:"path"`
		ResponseLength  int    `yaml:"response_length"`
		ResponseTimeout int    `yaml:"response_timeout"`
	} `yaml:"dictionary"`
}

var yamlConfig *YamlConfig

func LoadYamlConfig() (*YamlConfig, error) {
	if yamlConfig != nil {
		return yamlConfig, nil
	}

	configPath := "config.yaml"
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		configPath = filepath.Join("..", "config.yaml")
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			return nil, fmt.Errorf("config.yaml 文件未找到")
		}
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	yamlConfig = &YamlConfig{}
	if err := yaml.Unmarshal(data, yamlConfig); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	return yamlConfig, nil
}

func GetFeishuWebhook() (string, error) {
	config, err := LoadYamlConfig()
	if err != nil {
		return "", err
	}

	if config.Notify.Feishu == "" {
		return "", fmt.Errorf("飞书 webhook 未配置")
	}

	return config.Notify.Feishu, nil
}

// GetFofaAPI 获取Fofa API配置
func GetFofaAPI() (email, key string, err error) {
	config, err := LoadYamlConfig()
	if err != nil {
		return "", "", err
	}

	if config.APIKey.FofaEmail == "" {
		return "", "", fmt.Errorf("Fofa email 未配置")
	}
	if config.APIKey.Fofa == "" {
		return "", "", fmt.Errorf("Fofa API key 未配置")
	}

	return config.APIKey.FofaEmail, config.APIKey.Fofa, nil
}

// GetQuakeAPI 获取360 Quake API配置
func GetQuakeAPI() (string, error) {
	config, err := LoadYamlConfig()
	if err != nil {
		return "", err
	}

	if config.APIKey.Quake == "" {
		return "", fmt.Errorf("360 Quake API key 未配置")
	}

	return config.APIKey.Quake, nil
}

// GetHunterAPI 获取Hunter API配置
func GetHunterAPI() (string, error) {
	config, err := LoadYamlConfig()
	if err != nil {
		return "", err
	}

	if config.APIKey.Hunter == "" {
		return "", fmt.Errorf("Hunter API key 未配置")
	}

	return config.APIKey.Hunter, nil
}
