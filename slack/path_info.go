package slack

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/sethvargo/vault-auth-slack/version"
)

// pathInfoRead corresponds to READ auth/slack/info.
func (b *backend) pathInfoRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return &logical.Response{
		Data: map[string]interface{}{
			"name":    version.Name,
			"version": version.Version,
		},
	}, nil
}
