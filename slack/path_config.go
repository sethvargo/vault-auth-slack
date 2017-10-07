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

	// Get the client_id, secret, and redirect urls
	clientID := data.Get("client_id").(string)
	if clientID == "" {
		return errMissingField("client_id"), nil
	}
	clientSecret := data.Get("client_secret").(string)
	if clientSecret == "" {
		return errMissingField("client_secret"), nil
	}
	redirectURL := data.Get("redirect_url").(string)

	// Get the team
	teams := data.Get("teams").([]string)
	if len(teams) == 0 {
		return errMissingField("teams"), nil
	}

	// Get the tunable options
	allowRestrictedUsers := data.Get("allow_restricted_users").(bool)
	allowUltraRestrictedUsers := data.Get("allow_ultra_restricted_users").(bool)
	anyonePolicies := data.Get("anyone_policies").([]string)
	require2FA := data.Get("require_2fa").(bool)

	// Calculate TTLs, if supplied
	ttl := time.Duration(data.Get("ttl").(int)) * time.Second
	maxTTL := time.Duration(data.Get("max_ttl").(int)) * time.Second

	// Built the entry
	entry, err := logical.StorageEntryJSON("config", &config{
		AccessToken:               accessToken,
		ClientID:                  clientID,
		ClientSecret:              clientSecret,
		RedirectURL:               redirectURL,
		Teams:                     teams,
		AllowRestrictedUsers:      allowRestrictedUsers,
		AllowUltraRestrictedUsers: allowUltraRestrictedUsers,
		AnyonePolicies:            anyonePolicies,
		Require2FA:                require2FA,
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
