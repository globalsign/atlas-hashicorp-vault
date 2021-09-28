package atlas

import "fmt"

// String provides a reference to a string inline; this is useful when setting optional configuration.
func String(s string) *string {
	return &s
}

type APIError struct {
	Description string `json:"description"`
	StatusCode  int
}

func (e *APIError) Error() string {
	return fmt.Sprintf("ATLAS-API (%d): %s", e.StatusCode, e.Description)
}
