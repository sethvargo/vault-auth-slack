package slack

import (
	"time"

	"github.com/hashicorp/vault/logical"
	"github.com/pkg/errors"
)

// config represents the internally stored configuration information.
type config struct {
	// AccessToken is the OAuth access token to use for requests.
	AccessToken string `json:"access_token" structs:"-"`

	// ClientID is the client_id of the Slack application.
	ClientID string `json:"client_id" structs:"client_id,omitempty"`

	// ClientSecret is the client_secret of the Slack application.
	ClientSecret string `json:"client_secret" structs:"-"`

	// RedirectURL is the URL to redirect. This is used as an added layer of
	// security, since Slack also has its own redirect url.
	RedirectURL string `json:"redirect_url" structs:"redirect_url,omitempty"`

	// Teams are the name of the team. Users must be a member of at least one of
	// these teams in order to authenticate.
	Teams []string `json:"teams" structs:"teams,omitempty"`

	// Require2FA allows users that do not have two-factor authentication (2FA)
	// enabled in Slack to authenticate. The default is false.
	Require2FA bool `json:"require_2fa" structs:"require_2fa"`

	// AllowRestrictedUsers allows restricted users (AKA multi-channel guests) to
	// authenticate. The default is false.
	AllowRestrictedUsers bool `json:"allow_restricted_users" structs:"allow_restricted_users"`

	// AllowUltraRestrictedUsers allows ultra restricted users (AKA single-channel
	// guests) to authenticate. The default is false.
	AllowUltraRestrictedUsers bool `json:"allow_ultra_restricted_users" structs:"allow_ultra_restricted_users"`

	// AnyonePolicies is the list of policies to apply to any valid Slack member.
	AnyonePolicies []string `json:"anyone_policies" structs:"anyone_policies,omitempty"`

	// TTL and MaxTTL are the default TTLs.
	TTL    time.Duration `json:"ttl" structs:"ttl,omitempty"`
	MaxTTL time.Duration `json:"max_ttl" structs:"max_ttl,omitempty"`
}

// Config parses and returns the configuration data from the storage backend.
func (b *backend) Config(s logical.Storage) (*config, error) {
	entry, err := s.Get("config")
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get config from storage")
	}
	if entry == nil || len(entry.Value) == 0 {
		return nil, errors.New("no configuration in storage")
	}

	var result config
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, errors.Wrapf(err, "failed to decode configuration")
	}

	return &result, nil
}
