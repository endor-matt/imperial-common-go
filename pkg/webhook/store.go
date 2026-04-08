// Package webhook provides an in-memory store for incoming webhook payloads
// from weapons suppliers, intelligence partners, and fleet command systems.
package webhook

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Entry represents a stored webhook payload with metadata.
type Entry struct {
	Payload    string
	ReceivedAt time.Time
}

// Store holds the most recent webhook payload per event type.
type Store struct {
	mu      sync.RWMutex
	entries map[string]Entry
}

// NewStore creates a new webhook store.
func NewStore() *Store {
	return &Store{
		entries: make(map[string]Entry),
	}
}

// StorePayload saves an incoming webhook payload keyed by event type.
func (s *Store) StorePayload(eventType, payload string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	logrus.Infof("Storing webhook payload for event type: %s", eventType)
	s.entries[eventType] = Entry{
		Payload:    payload,
		ReceivedAt: time.Now(),
	}
}

// GetLatestPayload retrieves the most recent payload for the given event type
// and returns it as a parsed map. Returns nil if no payload exists.
func (s *Store) GetLatestPayload(eventType string) (map[string]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.entries[eventType]
	if !ok {
		logrus.Warnf("No webhook payload found for event type: %s", eventType)
		return nil, nil
	}

	logrus.Infof("Retrieved webhook payload for %s (received at %s)", eventType, entry.ReceivedAt)

	var result map[string]string
	if err := json.Unmarshal([]byte(entry.Payload), &result); err != nil {
		return nil, err
	}
	return result, nil
}

// GetRawPayload returns the raw JSON string for a given event type.
func (s *Store) GetRawPayload(eventType string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.entries[eventType]
	if !ok {
		return ""
	}
	return entry.Payload
}
