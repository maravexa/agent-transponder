package types

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ValidateTenantID accepts one literal filesystem component without rewriting
// identity. Empty identities are invalid; callers may explicitly choose _default
// only when no tenant was supplied by the identity provider.
func ValidateTenantID(id string) error {
	if !utf8.ValidString(id) || id == "" || id == "." || id == ".." || strings.ContainsAny(id, "/\\:") || strings.TrimSpace(id) != id {
		return fmt.Errorf("unsafe tenant ID %q", id)
	}
	for _, c := range id {
		if unicode.IsControl(c) {
			return fmt.Errorf("unsafe tenant ID %q", id)
		}
	}
	return nil
}
