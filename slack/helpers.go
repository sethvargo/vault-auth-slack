package slack

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
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

// validateFields verifies that no bad arguments were given to the request.
func validateFields(req *logical.Request, data *framework.FieldData) error {
	var unknownFields []string
	for k := range req.Data {
		if _, ok := data.Schema[k]; !ok {
			unknownFields = append(unknownFields, k)
		}
	}

	if len(unknownFields) > 0 {
		// Sort since this is a human error
		sort.Strings(unknownFields)

		return fmt.Errorf("unknown fields: %q", unknownFields)
	}

	return nil
}
