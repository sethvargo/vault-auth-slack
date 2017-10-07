package slack

import (
	log "github.com/mgutz/logxi/v1"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/pkg/errors"
)

// Factory creates a new usable instance of this auth method.
func Factory(c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(c)
	if err := b.Setup(c); err != nil {
		return nil, errors.Wrapf(err, "failed to create factory")
	}
	return b, nil
}

// backend is the actual backend
type backend struct {
	*framework.Backend
	logger log.Logger

	GroupsMap     *framework.PolicyMap
	UsergroupsMap *framework.PolicyMap
	UsersMap      *framework.PolicyMap
}

// Backend creates a new backend, mapping the proper paths, help information,
// and required callbacks.
func Backend(c *logical.BackendConfig) *backend {
	var b backend

	b.logger = c.Logger

	// GroupsMap maps private channels (like #team-ops) to a series of policies.
	b.GroupsMap = &framework.PolicyMap{
		PathMap: framework.PathMap{
			Name: "groups",
		},
		PolicyKey: "policy",
	}

	// UsergroupsMap maps usergroups (like @marketing) to a series of policies.
	b.UsergroupsMap = &framework.PolicyMap{
		PathMap: framework.PathMap{
			Name: "usergroups",
		},
		PolicyKey: "policy",
	}

	// UsersMap maps a slack username to a series of policies.
	b.UsersMap = &framework.PolicyMap{
		PathMap: framework.PathMap{
			Name: "users",
		},
		PolicyKey: "policy",
	}

	b.Backend = &framework.Backend{
		BackendType: logical.TypeCredential,

		AuthRenew: b.pathAuthRenew,

		Help: backendHelp,

		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{"login/*"},
		},

		Paths: func() []*framework.Path {
			var paths []*framework.Path

			// auth/slack/map/groups/*
			paths = append(paths, b.GroupsMap.Paths()...)

			// auth/slack/map/usergroups/*
			paths = append(paths, b.UsergroupsMap.Paths()...)

			// auth/slack/map/users/*
			paths = append(paths, b.UsersMap.Paths()...)

			// auth/slack/config
			paths = append(paths, &framework.Path{
				Pattern:      "config",
				HelpSynopsis: "Configuration such the team and ttls",
				HelpDescription: `

Read or writer configuration to Vault's storage backend such as OAuth
information, team, behavior configuration tunables, and TTLs. For example:

    $ vault write auth/slack/config \
        access_token="xoxp-2164918114..." \
        client_id="2164918114.249395258198" \
        client_secret="5950bfe46264d8485cb71b1d81551b75" \
        teams="HashiCorp"

For more information and examples, please see the online documentation.

`,

				Fields: map[string]*framework.FieldSchema{
					"access_token": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Slack OAuth access token for your Slack application.",
					},

					"client_id": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Slack client_id for your Slack application.",
					},

					"client_secret": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Slack client_secret for your Slack application.",
					},

					"redirect_url": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Slack redirect_url for your Slack application.",
					},

					"teams": &framework.FieldSchema{
						Type: framework.TypeCommaStringSlice,
						Description: "Comma-separated list of permitted Slack teams. The " +
							"user must be a member of at least one of these teams to " +
							"authenticate.",
					},

					"allow_restricted_users": &framework.FieldSchema{
						Type: framework.TypeBool,
						Description: "Allow restricted users (multi-channel guests) to " +
							"authenticate.",
					},

					"allow_ultra_restricted_users": &framework.FieldSchema{
						Type: framework.TypeBool,
						Description: "Allow ultra restricted users (single-channel " +
							"guests) to authenticate.",
					},

					"anyone_policies": &framework.FieldSchema{
						Type: framework.TypeCommaStringSlice,
						Description: "Comma-separated list of policies to apply to " +
							"everyone, even unmapped users.",
					},

					"require_2fa": &framework.FieldSchema{
						Type: framework.TypeBool,
						Description: "Require users have 2FA enabled on their Slack " +
							"account to authenticate.",
						Default: true,
					},

					"ttl": &framework.FieldSchema{
						Type:        framework.TypeDurationSecond,
						Description: "Duration after which authentication will expire.",
					},

					"max_ttl": &framework.FieldSchema{
						Type:        framework.TypeDurationSecond,
						Description: "Maximum duration after which authentication will expire.",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathConfigWrite,
					logical.ReadOperation:   b.pathConfigRead,
				},
			})

			// auth/slack/login/token
			paths = append(paths, &framework.Path{
				Pattern:      "login/token",
				HelpSynopsis: "Authenticate using a personal OAuth token",
				HelpDescription: `

Accepts a user's Slack personal OAuth token and performs a lookup on that user's
token to verify identity, group membership, etc. This identity information is
then used to map the user to policies in Vault.

`,
				Fields: map[string]*framework.FieldSchema{
					"token": &framework.FieldSchema{
						Type: framework.TypeString,
						Description: "Slack personal OAuth token to use for " +
							"authentication. Get your personal access token in your Slack " +
							"account settings.",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathAuthLogin,
				},
			})

			// auth/slack/login/oauth
			paths = append(paths, &framework.Path{
				Pattern:      "login/oauth",
				HelpSynopsis: "Authenticate using a 3-legged OAuth callback",
				HelpDescription: `

Accepts an OAuth callback from a "Login with Slack" request after the user
authorizes your applicaton. It exchanges a temporary token for a user's OAuth
token and then behaves exactly the same as /login using the resulting token for
the user.

The parameters are not documented here because they come directly from Slack.
You should not invoke this endpoint yourself - it should be used only as a
callback URL from an Slack user OAuth request.

`,
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.ReadOperation: b.pathAuthOAuth,
				},
			})

			return paths
		}(),
	}

	return &b
}

const backendHelp = `
The Slack auth method authenticates users using Slack groups, usergroups, or
user ID maps.

Users are automatically authenticated through a Slack team through the Slack
API. For example:

  * Allow anyone in the Slack team "hashicorp" in the private group "#ops"
    to authenticate to Vault and receive a token with the policy "operator".

  * Allow anyone in the Slack team "hashicorp" in the user group "@oncall"
    to authenticate to Vault and receive a token with the policy "enoc".

  * Allow the user "sethvargo" in the Slack team "hashicorp" to receive a
    root token.

Slack sometimes refers to teams as "workspaces". It is confusing. We are sorry.

Additionally, humans tend to think of slack groups and users as their
"display name" (e.g. @marketing), but Slack strongly recommends API clients use
IDs. For convenience, this auth method automatically maps those display names
to IDs at configuration time. As such, if you rename a group or user, they will
still continue to receive the same permissions.
`
