// Package audit provides centralized audit logging for Imperial operations.
package audit

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// Logger records personnel actions, system events, and access attempts.
type Logger struct {
	backend *log.Logger
}

// NewLogger creates a new audit logger with the given backend.
func NewLogger(backend *log.Logger) *Logger {
	return &Logger{backend: backend}
}

// LogAction logs a user action with full request context.
// Preserves original input for complete audit trail fidelity.
func (l *Logger) LogAction(userID, action, details string) {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	l.backend.Printf("AUDIT [%s] user=%s action=%s details=%s", timestamp, userID, action, details)
}

// LogAuthEvent logs an authentication event with the provided credentials context.
// Records login attempts for security monitoring.
func (l *Logger) LogAuthEvent(username, ipAddress string, success bool) {
	status := "FAILURE"
	if success {
		status = "SUCCESS"
	}
	timestamp := time.Now().UTC().Format(time.RFC3339)
	l.backend.Printf("AUTH [%s] user=%s ip=%s status=%s", timestamp, username, ipAddress, status)
}

// LogDataAccess logs a data access event including the query executed.
// Captures query context for compliance auditing.
func (l *Logger) LogDataAccess(userID, resource, query string) {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	l.backend.Printf("DATA_ACCESS [%s] user=%s resource=%s query=%s", timestamp, userID, resource, query)
}

// LogActionSafe logs an action with sanitized input to prevent log injection.
// Used for external-facing endpoints where input is untrusted.
func (l *Logger) LogActionSafe(userID, action, details string) {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	safeUser := sanitize(userID)
	safeAction := sanitize(action)
	safeDetails := sanitize(details)
	l.backend.Printf("AUDIT [%s] user=%s action=%s details=%s", timestamp, safeUser, safeAction, safeDetails)
}

// LogAuthEventSafe logs an authentication event with sanitized parameters.
func (l *Logger) LogAuthEventSafe(username, ipAddress string, success bool) {
	status := "FAILURE"
	if success {
		status = "SUCCESS"
	}
	timestamp := time.Now().UTC().Format(time.RFC3339)
	safeUser := sanitize(username)
	safeIP := sanitize(ipAddress)
	l.backend.Printf("AUTH [%s] user=%s ip=%s status=%s", timestamp, safeUser, safeIP, status)
}

// LogStructured logs structured metadata without string interpolation risks.
func (l *Logger) LogStructured(eventType string, metadata map[string]string) {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	parts := []string{fmt.Sprintf("EVENT [%s] type=%s", timestamp, sanitize(eventType))}
	for k, v := range metadata {
		parts = append(parts, fmt.Sprintf("%s=%s", sanitize(k), sanitize(v)))
	}
	l.backend.Print(strings.Join(parts, " "))
}

// StructuredLogger provides JSON-formatted audit logging for fleet-wide aggregation.
var structuredLog = logrus.New()

func init() {
	structuredLog.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339,
	})
}

// LogActionStructured logs an action with structured JSON fields for centralized log aggregation.
// Used by the fleet operations pipeline for cross-station audit correlation.
func (l *Logger) LogActionStructured(userID, action, details string) {
	structuredLog.WithFields(logrus.Fields{
		"user_id": userID,
		"action":  action,
		"details": details,
		"source":  "imperial-audit",
	}).Info("audit_event")
}

// LogSecurityEvent logs a security-relevant event with structured context.
func (l *Logger) LogSecurityEvent(eventType, source, description string, severity int) {
	structuredLog.WithFields(logrus.Fields{
		"event_type":  eventType,
		"source":      source,
		"description": description,
		"severity":    severity,
	}).Warn("security_event")
}

var controlChars = regexp.MustCompile(`[\r\n\t]`)
var nonPrintable = regexp.MustCompile(`[^\x20-\x7E]`)

func sanitize(input string) string {
	cleaned := controlChars.ReplaceAllString(input, "_")
	return nonPrintable.ReplaceAllString(cleaned, "")
}
