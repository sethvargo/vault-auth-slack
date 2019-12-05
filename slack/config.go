package slack

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/nlopes/slack"
	"github.com/pkg/errors"
)

// config represents the internally stored configuration information.
type config struct {
	// AccessToken is the OAuth access token to use for requests.
	AccessToken string `json:"access_token" structs:"-"`

	// Endpoint is the slack endpoint. This is only useful for testing or if you
	// run your own Slack installation.
	Endpoint string `json:"endpoint" structs:"endpoint"`

	// Teams are the name of the team. Users must be a member of at least one of
	// these teams in order to authenticate.
	Teams []string `json:"teams" structs:"teams,omitempty"`

	// AllowBotUsers allows bot users to authenticate. The default is false.
	AllowBotUsers bool `json:"allow_bot_users" structs:"allow_bot_users"`

	// AllowNon2FA allows users that do not have two-factor authentication (2FA)
	// enabled in Slack to authenticate. The default is false.
	AllowNon2FA bool `json:"allow_non_2fa" structs:"allow_non_2fa"`

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
func (b *backend) Config(ctx context.Context, s logical.Storage) (*config, error) {
	entry, err := s.Get(ctx, "config")
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

func OptionSlackEndpoint(u string) func(*slack.Client) {
	return func(c *slack.Client) {
		if u != "" {
			slack.OptionAPIURL(u)(c)
		}
	}
}
