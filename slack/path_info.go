package slack

import (
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/hashicorp/vault/version"
)

// pathInfoRead corresponds to READ auth/slack/info.
func (b *backend) pathInfoRead(req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return &logical.Response{
		Data: map[string]interface{}{
			"commit":  version.GitCommit,
			"version": version.Version,
		},
	}, nil
}
