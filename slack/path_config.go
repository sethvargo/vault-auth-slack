package slack

import (
	"time"

	"github.com/fatih/structs"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/pkg/errors"
)

// pathConfigRead corresponds to READ auth/slack/config.
func (b *backend) pathConfigRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.Config(req.Storage)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get configuration from storage")
	}

	// TTLs are stored as seconds
	config.TTL /= time.Second
	config.MaxTTL /= time.Second

	resp := &logical.Response{
		Data: structs.New(config).Map(),
	}
	return resp, nil
}

// pathConfigRead corresponds to POST auth/slack/config.
func (b *backend) pathConfigWrite(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Get the access token
	accessToken := data.Get("access_token").(string)
	if accessToken == "" {
		return errMissingField("access_token"), nil
	}

	// Get the team
	teams := data.Get("teams").([]string)
	if len(teams) == 0 {
		return errMissingField("teams"), nil
	}

	// Get the tunable options
	allowBotUsers := data.Get("allow_bot_users").(bool)
	allowNon2FA := data.Get("allow_non_2fa").(bool)
	allowRestrictedUsers := data.Get("allow_restricted_users").(bool)
	allowUltraRestrictedUsers := data.Get("allow_ultra_restricted_users").(bool)
	anyonePolicies := data.Get("anyone_policies").([]string)

	// Calculate TTLs, if supplied
	ttl := time.Duration(data.Get("ttl").(int)) * time.Second
	maxTTL := time.Duration(data.Get("max_ttl").(int)) * time.Second

	// Built the entry
	entry, err := logical.StorageEntryJSON("config", &config{
		AccessToken:               accessToken,
		Teams:                     teams,
		AllowBotUsers:             allowBotUsers,
		AllowNon2FA:               allowNon2FA,
		AllowRestrictedUsers:      allowRestrictedUsers,
		AllowUltraRestrictedUsers: allowUltraRestrictedUsers,
		AnyonePolicies:            anyonePolicies,
		TTL:                       ttl,
		MaxTTL:                    maxTTL,
	})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to generate storage entry")
	}

	if err := req.Storage.Put(entry); err != nil {
		return nil, errors.Wrapf(err, "failed to write configuration to storage")
	}
	return nil, nil
}
