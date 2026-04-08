// Package feed provides clients for fetching real-time data feeds from
// external weapons supplier and intelligence partner APIs.
package feed

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// Client fetches operational data from external supplier and intelligence feeds.
type Client struct {
	httpClient *http.Client
	baseURL    string
}

// NewClient creates a new data feed client targeting the given base URL.
func NewClient(baseURL string) *Client {
	return &Client{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		baseURL:    baseURL,
	}
}

// SupplierRecord represents a single pricing record from the supplier feed.
type SupplierRecord struct {
	ItemName string `json:"item_name"`
	Category string `json:"category"`
	Price    string `json:"price"`
	Unit     string `json:"unit"`
}

// FetchSupplierData retrieves the latest weapons supplier pricing from the
// external feed API. Returns structured records from the API response.
// The returned data is attacker-influenced if the external API is compromised.
func (c *Client) FetchSupplierData(supplierID string) ([]SupplierRecord, error) {
	url := fmt.Sprintf("%s/api/suppliers/%s/inventory", c.baseURL, supplierID)
	logrus.Infof("Fetching supplier data from feed: %s", url)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("supplier feed request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read supplier feed response: %w", err)
	}

	var records []SupplierRecord
	if err := json.Unmarshal(body, &records); err != nil {
		return nil, fmt.Errorf("failed to parse supplier feed data: %w", err)
	}

	logrus.Infof("Received %d supplier records for %s", len(records), supplierID)
	return records, nil
}

// TelemetryRecord represents a telemetry data point from an external sensor feed.
type TelemetryRecord struct {
	SensorID string `json:"sensor_id"`
	Reading  string `json:"reading"`
	FilePath string `json:"file_path"`
}

// FetchTelemetryData retrieves sensor telemetry from the external intelligence feed.
func (c *Client) FetchTelemetryData(sectorID string) ([]TelemetryRecord, error) {
	url := fmt.Sprintf("%s/api/telemetry/%s/readings", c.baseURL, sectorID)
	logrus.Infof("Fetching telemetry data from feed: %s", url)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("telemetry feed request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read telemetry feed response: %w", err)
	}

	var records []TelemetryRecord
	if err := json.Unmarshal(body, &records); err != nil {
		return nil, fmt.Errorf("failed to parse telemetry data: %w", err)
	}

	logrus.Infof("Received %d telemetry records for sector %s", len(records), sectorID)
	return records, nil
}
