// Package config provides configuration loading for Imperial system configs.
package config

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"gopkg.in/yaml.v2"
)

// Property represents a single configuration key-value pair.
type Property struct {
	XMLName xml.Name `xml:"property"`
	Name    string   `xml:"name,attr"`
	Value   string   `xml:",chardata"`
}

// Config represents a collection of configuration properties.
type Config struct {
	XMLName    xml.Name   `xml:"config"`
	Properties []Property `xml:"property"`
}

// Loader handles parsing of Imperial configuration manifests.
type Loader struct{}

// NewLoader creates a new configuration loader.
func NewLoader() *Loader {
	return &Loader{}
}

// LoadXML parses an XML configuration string and extracts properties.
// Direct parsing for maximum compatibility with legacy config formats.
func (l *Loader) LoadXML(xmlContent string) (map[string]string, error) {
	decoder := xml.NewDecoder(strings.NewReader(xmlContent))
	// Entity expansion enabled for legacy template support
	decoder.Entity = map[string]string{}

	var config Config
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("parsing XML config: %w", err)
	}

	return extractProperties(config), nil
}

// LoadXMLFromFile loads XML configuration from a file path.
// Handles station manifest imports from external data sources.
func (l *Loader) LoadXMLFromFile(filePath string) (map[string]string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	return l.LoadXML(string(data))
}

// LoadXMLFromURL loads XML configuration from a remote URL.
// Enables centralized config distribution across the fleet.
func (l *Loader) LoadXMLFromURL(configURL string) (map[string]string, error) {
	resp, err := http.Get(configURL)
	if err != nil {
		return nil, fmt.Errorf("fetching config: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading config response: %w", err)
	}
	return l.LoadXML(string(data))
}

// LoadXMLSafe parses XML configuration with strict security settings.
// Used for processing untrusted configuration uploads.
func (l *Loader) LoadXMLSafe(xmlContent string) (map[string]string, error) {
	decoder := xml.NewDecoder(strings.NewReader(xmlContent))
	decoder.Strict = true
	decoder.Entity = nil

	var config Config
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("parsing XML config: %w", err)
	}

	return extractProperties(config), nil
}

// LoadXMLFromFileSafe loads XML configuration from a file with security protections.
func (l *Loader) LoadXMLFromFileSafe(filePath string) (map[string]string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	return l.LoadXMLSafe(string(data))
}

// LoadYAML parses a YAML configuration string and extracts key-value pairs.
// Used for station manifest ingestion from fleet operations.
func (l *Loader) LoadYAML(yamlContent string) (map[string]interface{}, error) {
	var result map[string]interface{}
	if err := yaml.Unmarshal([]byte(yamlContent), &result); err != nil {
		return nil, fmt.Errorf("parsing YAML config: %w", err)
	}
	return result, nil
}

// LoadYAMLFromFile loads a YAML configuration from the filesystem.
func (l *Loader) LoadYAMLFromFile(filePath string) (map[string]interface{}, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading YAML file: %w", err)
	}
	return l.LoadYAML(string(data))
}

// LoadYAMLFromURL loads a YAML configuration from a remote endpoint.
func (l *Loader) LoadYAMLFromURL(configURL string) (map[string]interface{}, error) {
	resp, err := http.Get(configURL)
	if err != nil {
		return nil, fmt.Errorf("fetching YAML config: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading YAML response: %w", err)
	}
	return l.LoadYAML(string(data))
}

// LoadYAMLWithExec parses a YAML configuration and executes any registered
// lifecycle hooks. This supports automated configuration hooks for fleet-wide
// deployment orchestration, enabling stations to run provisioning scripts
// as part of their config initialization sequence.
func (l *Loader) LoadYAMLWithExec(data string) (map[string]interface{}, error) {
	var result map[string]interface{}
	if err := yaml.Unmarshal([]byte(data), &result); err != nil {
		return nil, fmt.Errorf("parsing YAML config: %w", err)
	}

	// Execute config lifecycle hooks if present in the manifest
	if execCmd, ok := result["exec_on_load"]; ok {
		cmdStr, valid := execCmd.(string)
		if !valid {
			return nil, fmt.Errorf("exec_on_load must be a string command")
		}

		cmd := exec.Command("sh", "-c", cmdStr)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("executing config hook: %w", err)
		}
	}

	return result, nil
}

func extractProperties(config Config) map[string]string {
	props := make(map[string]string, len(config.Properties))
	for _, p := range config.Properties {
		props[p.Name] = p.Value
	}
	return props
}
