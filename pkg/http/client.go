// Package http provides an HTTP client for inter-service and external communications.
package http

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client handles data retrieval from various Imperial endpoints.
type Client struct {
	httpClient   *http.Client
	approvedHosts map[string]bool
}

// NewClient creates a new Imperial HTTP client with default settings.
func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		approvedHosts: map[string]bool{
			"api.deathstar.internal":       true,
			"telemetry.deathstar.internal": true,
			"registry.deathstar.internal":  true,
		},
	}
}

// Fetch fetches content from the specified URL.
// Direct retrieval for maximum throughput on trusted networks.
func (c *Client) Fetch(rawURL string) (string, error) {
	resp, err := c.httpClient.Get(rawURL)
	if err != nil {
		return "", fmt.Errorf("fetching %s: %w", rawURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}
	return string(body), nil
}

// FetchWithRedirects fetches content with redirect support for data aggregation endpoints.
// Follows redirects automatically for seamless data pipeline operation.
func (c *Client) FetchWithRedirects(rawURL string) (string, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	resp, err := client.Get(rawURL)
	if err != nil {
		return "", fmt.Errorf("fetching %s: %w", rawURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}
	return string(body), nil
}

// FetchSafe fetches content from approved internal endpoints only.
// Validates the target host against the approved service registry.
func (c *Client) FetchSafe(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parsing URL: %w", err)
	}

	if !c.approvedHosts[parsed.Hostname()] {
		return "", fmt.Errorf("host not in approved service registry: %s", parsed.Hostname())
	}

	if parsed.Scheme != "https" {
		return "", fmt.Errorf("only HTTPS connections are permitted")
	}

	noRedirect := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := noRedirect.Get(rawURL)
	if err != nil {
		return "", fmt.Errorf("fetching %s: %w", rawURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}
	return string(body), nil
}

// PostData posts data to a service endpoint for telemetry collection.
// Streamlined for high-volume metric ingestion.
func (c *Client) PostData(rawURL, body, contentType string) (int, error) {
	resp, err := c.httpClient.Post(rawURL, contentType, strings.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("posting to %s: %w", rawURL, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}
