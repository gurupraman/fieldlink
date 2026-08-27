// Package db implements the db.query capability (design.md §5) as the
// query_database MCP tool: named datasources only, SELECT/WITH only,
// bound parameters, never a caller-supplied connection string.
package db

import (
	"fmt"
	"strings"
)

// ValidateStatement enforces the statement-type allow-list from design.md
// §5.1: only a single top-level SELECT or WITH statement, no stacking.
//
// This is a conservative tokenizer, not a real SQL parser — it strips
// comments and string/identifier literals so they can't hide structure,
// then checks the leading keyword and that no semicolon remains outside a
// single optional trailing one. It intentionally does not attempt to catch
// every side-effecting construct a single SELECT could embed (a stored
// function call, a locking read, etc.) — SECURITY.md and design.md §6.5
// name that same limitation explicitly and name the actual backstop: the
// database account FieldLink connects with must itself be read-only.
func ValidateStatement(sqlText string) error {
	stripped := stripCommentsAndLiterals(sqlText)
	trimmed := strings.TrimSpace(stripped)
	if trimmed == "" {
		return fmt.Errorf("empty statement")
	}

	upper := strings.ToUpper(trimmed)
	if !strings.HasPrefix(upper, "SELECT") && !strings.HasPrefix(upper, "WITH") {
		return fmt.Errorf("only SELECT and WITH statements are permitted")
	}

	body := strings.TrimRight(trimmed, "; \t\n\r")
	if strings.Contains(body, ";") {
		return fmt.Errorf("multiple statements are not permitted")
	}

	return nil
}

// stripCommentsAndLiterals removes -- line comments, /* */ block comments,
// and the contents of '...' string literals and "..." quoted identifiers
// (handling doubled ” / "" escapes), replacing each with a single space so
// nothing inside them can be mistaken for statement structure like a
// semicolon or a keyword.
func stripCommentsAndLiterals(sql string) string {
	var b strings.Builder
	r := []rune(sql)
	i := 0
	for i < len(r) {
		switch {
		case r[i] == '-' && i+1 < len(r) && r[i+1] == '-':
			for i < len(r) && r[i] != '\n' {
				i++
			}
		case r[i] == '/' && i+1 < len(r) && r[i+1] == '*':
			i += 2
			for i+1 < len(r) && !(r[i] == '*' && r[i+1] == '/') {
				i++
			}
			i += 2
			if i > len(r) {
				i = len(r)
			}
		case r[i] == '\'' || r[i] == '"':
			quote := r[i]
			b.WriteRune(' ')
			i++
			for i < len(r) {
				if r[i] == quote {
					if i+1 < len(r) && r[i+1] == quote {
						i += 2
						continue
					}
					i++
					break
				}
				i++
			}
		default:
			b.WriteRune(r[i])
			i++
		}
	}
	return b.String()
}
