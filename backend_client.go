package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type BackendAuthRequest struct {
	Username string `json:"username"`
	ApiKey   string `json:"api_key"`
}

type BackendAuthResponse struct {
	PasswordHash string `json:"password_hash"`
	UpstreamHost string `json:"upstream_host"`
	UpstreamPort string `json:"upstream_port"`
	UpstreamUser string `json:"upstream_user"`
	UpstreamPass string `json:"upstream_pass"`
}

type BackendClient struct {
	apiURL     string
	apiKey     string
	httpClient *http.Client
}

func NewBackendClient() *BackendClient {
	apiURL := os.Getenv("BACKEND_SSH_API_URL")
	apiKey := os.Getenv("BACKEND_SSH_API_KEY")
	
	return &BackendClient{
		apiURL: apiURL,
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (bc *BackendClient) GetUserAuth(username string) (*BackendAuthResponse, error) {
	reqBody := BackendAuthRequest{
		Username: username,
		ApiKey:   bc.apiKey,
	}
	
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	
	req, err := http.NewRequest("POST", bc.apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := bc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("backend returned status %d: %s", resp.StatusCode, string(body))
	}
	
	var authResp BackendAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	
	return &authResp, nil
}
