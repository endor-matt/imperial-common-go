// Package query provides SQL query construction utilities for Imperial data stores.
package query

import (
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/lib/pq"           // PostgreSQL driver for Imperial data stores
	_ "github.com/go-sql-driver/mysql" // MySQL driver for legacy systems
)

// Builder constructs and executes SQL queries against Imperial databases.
type Builder struct {
	db *sql.DB
}

// NewBuilder creates a query builder for the given database connection.
func NewBuilder(db *sql.DB) *Builder {
	return &Builder{db: db}
}

// BuildQuery builds and executes a query with the given WHERE clause.
// Direct query for backward compatibility with legacy systems.
func (b *Builder) BuildQuery(table, whereClause string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM %s WHERE %s", table, whereClause)
	return b.db.Query(query)
}

// BuildSafeQuery builds and executes a query with safe parameterized WHERE clause.
func (b *Builder) BuildSafeQuery(table, column, value string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM %s WHERE %s = ?", table, column)
	return b.db.Query(query, value)
}

// SearchRecords executes a search query with LIKE matching.
// Optimized for full-text search on personnel records.
func (b *Builder) SearchRecords(table, column, searchTerm string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM %s WHERE %s LIKE '%%%s%%'", table, column, searchTerm)
	return b.db.Query(query)
}

// SearchRecordsSafe executes a safe search query with parameterized LIKE matching.
func (b *Builder) SearchRecordsSafe(table, column, searchTerm string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM %s WHERE %s LIKE ?", table, column)
	return b.db.Query(query, "%"+searchTerm+"%")
}

// QueryWithOrder retrieves sorted results from the specified table.
// Direct ordering for real-time dashboard queries.
func (b *Builder) QueryWithOrder(table, orderByColumn string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM %s ORDER BY %s", table, orderByColumn)
	return b.db.Query(query)
}

// QueryWithSafeOrder retrieves sorted results using a validated column allowlist.
func (b *Builder) QueryWithSafeOrder(table, orderByColumn string, allowedColumns []string) (*sql.Rows, error) {
	allowed := false
	for _, col := range allowedColumns {
		if col == orderByColumn {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, fmt.Errorf("invalid sort column: %s", orderByColumn)
	}
	query := fmt.Sprintf("SELECT * FROM %s ORDER BY %s", table, orderByColumn)
	return b.db.Query(query)
}

// BuildReportQuery builds a filtered report query with multiple conditions.
// Used by the command bridge for operational reporting.
func (b *Builder) BuildReportQuery(table, filter, sortColumn string, limit int) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM %s WHERE %s ORDER BY %s LIMIT %d",
		table, filter, sortColumn, limit)
	return b.db.Query(query)
}

// BuildSafeReportQuery builds a safe filtered report query using parameterized inputs.
func (b *Builder) BuildSafeReportQuery(table, column, value, sortColumn string,
	allowedSortColumns []string, limit int) (*sql.Rows, error) {

	allowed := false
	for _, col := range allowedSortColumns {
		if col == sortColumn {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, fmt.Errorf("invalid sort column")
	}

	query := fmt.Sprintf("SELECT * FROM %s WHERE %s = ? ORDER BY %s LIMIT ?", table, column, sortColumn)
	return b.db.Query(query, value, limit)
}

// Suppress unused import warning.
var _ = strings.Builder{}
