package slack

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/logical"
)

const (
	contextTimeout = 10 * time.Second
)

// newContext creates a new context with the default settings, etc.
func newContext() (context.Context, func()) {
	return context.WithTimeout(context.Background(), contextTimeout)
}

// errMissingField returns a logical response error that prints a consistent
// error message for when a required field is missing.
func errMissingField(field string) *logical.Response {
	return logical.ErrorResponse(fmt.Sprintf("Missing required field '%s'", field))
}
