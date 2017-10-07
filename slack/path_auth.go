package slack

import (
	"fmt"
	"strings"

	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/nlopes/slack"
	"github.com/pkg/errors"
)

// verifyResp is a wrapper around fields returned from verifyCreds.
type verifyResp struct {
	Policies []string
	User     *slack.User
}

// pathAuthLogin accepts a user's personal OAuth token and validates the user's
// identity to generate a Vault token.
func (b *backend) pathAuthLogin(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	token := d.Get("token").(string)
	if token == "" {
		return errMissingField("token"), nil
	}

	return b.verifyCredsResp(req, token)
}

// pathAuthOAuth accepts a "login with slack" payload and converts that to a
// user oauth token for validating the user's identity.
func (b *backend) pathAuthOAuth(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Make sure the response was successful
	if err, ok := d.GetOk("error"); ok {
		return logical.ErrorResponse(fmt.Sprintf("oauth request failed: %s", err)), nil
	}

	// Get the code
	code := strings.TrimSpace(req.Query.Get("code"))
	if code == "" {
		return errMissingField("code"), nil
	}

	// Get the configuration
	config, err := b.Config(req.Storage)
	if err != nil {
		return nil, err
	}

	ctx, cancel := newContext()
	defer cancel()
	resp, err := slack.GetOAuthResponseContext(ctx, config.ClientID, config.ClientSecret, code, "", false)
	if err != nil {
		err = errors.Wrapf(err, "failed oauth attempt")
		return logical.ErrorResponse(err.Error()), nil
	}

	return b.verifyCredsResp(req, resp.AccessToken)
}

// pathAuthRenew is used to renew authentication.
func (b *backend) pathAuthRenew(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Verify we received auth
	if req.Auth == nil {
		return nil, fmt.Errorf("request auth was nil")
	}

	// Grab the token
	tokenRaw, ok := req.Auth.InternalData["token"]
	if !ok {
		return nil, fmt.Errorf("no internal token found in the store")
	}
	token, ok := tokenRaw.(string)
	if !ok {
		return nil, fmt.Errorf("stored access token is not a string")
	}

	// Verify the creds using internal data
	creds, err := b.verifyCreds(req, token)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to validate stored credentials")
	}

	// Make sure the policies haven't changed. If they have, inform the user to
	// re-authenticate.
	if !policyutil.EquivalentPolicies(creds.Policies, req.Auth.Policies) {
		return nil, fmt.Errorf("policies no longer match")
	}

	// Get the TTLs
	config, err := b.Config(req.Storage)
	if err != nil {
		return nil, err
	}

	// Extend the lease
	return framework.LeaseExtend(config.TTL, config.MaxTTL, b.System())(req, d)
}

// verifyCreds verifies the given credentials.
func (b *backend) verifyCreds(req *logical.Request, token string) (*verifyResp, error) {
	config, err := b.Config(req.Storage)
	if err != nil {
		return nil, err
	}

	// Validate that the team was given to match on.
	if len(config.Teams) == 0 {
		return nil, fmt.Errorf("configure the Slack provider first")
	}

	// Create the client
	client := slack.New(token)

	// Get self
	ctx, cancel := newContext()
	defer cancel()
	resp, err := client.AuthTestContext(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to lookup auth")
	}

	// Verify the team is in the list
	found := false
	for _, t := range config.Teams {
		if resp.TeamID == t || resp.Team == t {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("'<@%s|%s>' is not a registered team. Registered teams are: %q",
			resp.TeamID, resp.Team, config.Teams)
	}

	// Create a new client using Vault's token to lookup more information
	client = slack.New(config.AccessToken)

	// Lookup more information about the user
	ctx, cancel = newContext()
	defer cancel()
	user, err := client.GetUserInfoContext(ctx, resp.UserID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to lookup user info")
	}

	switch {
	case user.Deleted:
		return nil, fmt.Errorf("user is deleted")
	case user.IsBot:
		return nil, fmt.Errorf("user is a bot")
	case !user.Has2FA && config.Require2FA:
		return nil, fmt.Errorf("user does not have 2FA enabled")
	case user.IsRestricted && !config.AllowRestrictedUsers:
		return nil, fmt.Errorf("user is a restricted user")
	case user.IsUltraRestricted && !config.AllowUltraRestrictedUsers:
		return nil, fmt.Errorf("user is an ultra restricted user")
	}

	// Groups are "private channels" like #team-ops
	ctx, cancel = newContext()
	defer cancel()

	groups, err := client.GetGroupsContext(ctx, true)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list groups")
	}
	groupIDs := make([]string, 0, len(groups)*2)
	for _, g := range groups {
		groupIDs = append(groupIDs, g.ID)
		groupIDs = append(groupIDs, g.Name)
	}

	// UserGroups are mentioned at once like @marketing or @engineering
	ctx, cancel = newContext()
	defer cancel()

	usergroups, err := client.GetUserGroupsContext(ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list usergroups")
	}
	usergroupIDs := make([]string, 0, len(usergroups)*2)
	for _, u := range usergroups {
		usergroupIDs = append(usergroupIDs, u.ID)
		usergroupIDs = append(usergroupIDs, u.Name)
	}

	// Accumulate all policies
	groupPolicies, err := b.GroupsMap.Policies(req.Storage, groupIDs...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list group policies")
	}
	usergroupPolicies, err := b.UsergroupsMap.Policies(req.Storage, usergroupIDs...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list usergroup policies")
	}
	userPolicies, err := b.UsersMap.Policies(req.Storage, user.Name)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list user policies")
	}
	policies := make([]string, 0, len(groupPolicies)+len(usergroupPolicies))
	policies = append(policies, groupPolicies...)
	policies = append(policies, usergroupPolicies...)
	policies = append(policies, userPolicies...)

	// Append the default policies
	policies = append(policies, config.AnyonePolicies...)

	// Unique, since we want to remove duplicates and that will cause errors when
	// we compare policies later.
	uniq := map[string]struct{}{}
	for _, v := range policies {
		if _, ok := uniq[v]; !ok {
			uniq[v] = struct{}{}
		}
	}
	newPolicies := make([]string, 0, len(uniq))
	for k := range uniq {
		newPolicies = append(newPolicies, k)
	}
	policies = newPolicies

	return &verifyResp{
		Policies: policies,
		User:     user,
	}, nil
}

// verifyCredsResp invokes verifyCreds and wraps the result in the correct
// *logical.Response object.
func (b *backend) verifyCredsResp(req *logical.Request, token string) (*logical.Response, error) {
	// Verify the credentails
	creds, err := b.verifyCreds(req, token)
	if err != nil {
		err = errors.Wrapf(err, "failed to verify credentials")
		return logical.ErrorResponse(err.Error()), nil
	}

	// If there are no policies attached, that means we should not issue a token
	if len(creds.Policies) == 0 {
		return nil, logical.ErrPermissionDenied
	}

	// Get configuration
	config, err := b.Config(req.Storage)
	if err != nil {
		return nil, err
	}

	// Get TTLs
	ttl, _, err := b.SanitizeTTLStr(config.TTL.String(), config.MaxTTL.String())
	if err != nil {
		return nil, errors.Wrapf(err, "failed to sanitize TTLs")
	}

	// Compose the response
	return &logical.Response{
		Auth: &logical.Auth{
			InternalData: map[string]interface{}{
				"token": token,
			},
			Policies: creds.Policies,
			Metadata: map[string]string{
				"slack_user_id":        creds.User.ID,
				"slack_user_name":      creds.User.Name,
				"slack_user_real_name": creds.User.RealName,
			},
			DisplayName: creds.User.Name,
			LeaseOptions: logical.LeaseOptions{
				TTL:       ttl,
				Renewable: true,
			},
		},
	}, nil
}
