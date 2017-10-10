package slack

import (
	"time"

	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/nlopes/slack"
	"github.com/pkg/errors"
)

// verifyResp is a wrapper around fields returned from verifyCreds.
type verifyResp struct {
	policies []string
	user     *slack.User
	team     *slack.Team

	ttl    time.Duration
	maxTTL time.Duration
}

// pathAuthLogin accepts a user's personal OAuth token and validates the user's
// identity to generate a Vault token.
func (b *backend) pathAuthLogin(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Validate we didn't get extraneous fields
	if err := validateFields(req, d); err != nil {
		return nil, logical.CodedError(422, err.Error())
	}

	// Make sure we have a token
	token := d.Get("token").(string)
	if token == "" {
		return errMissingField("token"), nil
	}

	// Verify the credentails
	creds, err := b.verifyCreds(req, token)
	if err != nil {
		if err, ok := err.(logical.HTTPCodedError); ok {
			return nil, err
		}
		return nil, logical.ErrPermissionDenied
	}

	// Compose the response
	return &logical.Response{
		Auth: &logical.Auth{
			InternalData: map[string]interface{}{
				"slack_token": token,
			},
			Policies: creds.policies,
			Metadata: map[string]string{
				"slack_team_id":        creds.team.ID,
				"slack_team_name":      creds.team.Name,
				"slack_user_id":        creds.user.ID,
				"slack_user_name":      creds.user.Name,
				"slack_user_real_name": creds.user.RealName,
			},
			DisplayName: creds.user.Name,
			LeaseOptions: logical.LeaseOptions{
				TTL:       creds.ttl,
				Renewable: true,
			},
		},
	}, nil
}

// pathAuthRenew is used to renew authentication.
func (b *backend) pathAuthRenew(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Verify we received auth
	if req.Auth == nil {
		return nil, errors.New("request auth was nil")
	}

	// Grab the token
	tokenRaw, ok := req.Auth.InternalData["slack_token"]
	if !ok {
		return nil, errors.New("no internal token found in the store")
	}
	token, ok := tokenRaw.(string)
	if !ok {
		return nil, errors.New("stored access token is not a string")
	}

	// Verify the credentails
	creds, err := b.verifyCreds(req, token)
	if err != nil {
		if err, ok := err.(logical.HTTPCodedError); ok {
			return nil, err
		}
		return nil, logical.ErrPermissionDenied
	}

	// Make sure the policies haven't changed. If they have, inform the user to
	// re-authenticate.
	if !policyutil.EquivalentPolicies(creds.policies, req.Auth.Policies) {
		return nil, errors.New("policies no longer match")
	}

	// Extend the lease
	return framework.LeaseExtend(creds.ttl, creds.maxTTL, b.System())(req, d)
}

// verifyCreds verifies the given credentials.
func (b *backend) verifyCreds(req *logical.Request, token string) (*verifyResp, error) {
	config, err := b.Config(req.Storage)
	if err != nil {
		return nil, err
	}

	// Create the client
	client := slack.New(token)

	// Get self
	ctx, cancel := newContext()
	defer cancel()
	resp, err := client.AuthTestContext(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "auth.test")
	}

	// Create the team
	team := &slack.Team{
		ID:   resp.TeamID,
		Name: resp.Team,
	}

	// Verify the team is in the list
	found := false
	for _, t := range config.Teams {
		if team.ID == t || team.Name == t {
			found = true
			break
		}
	}
	if !found {
		return nil, logical.CodedError(403, "user is not part of any registered teams")
	}

	// Create a new client using Vault's token to lookup more information
	client = slack.New(config.AccessToken)

	// Lookup more information about the user
	ctx, cancel = newContext()
	defer cancel()
	user, err := client.GetUserInfoContext(ctx, resp.UserID)
	if err != nil {
		return nil, errors.Wrap(err, "users.list")
	}

	switch {
	case user.Deleted:
		return nil, logical.CodedError(403, "user is deleted")
	case user.IsBot && !config.AllowBotUsers:
		return nil, logical.CodedError(403, "user is a bot")
	case !user.Has2FA && !config.AllowNon2FA:
		return nil, logical.CodedError(403, "user does not have 2FA enabled")
	case user.IsRestricted && !config.AllowRestrictedUsers:
		return nil, logical.CodedError(403, "user is a restricted user")
	case user.IsUltraRestricted && !config.AllowUltraRestrictedUsers:
		return nil, logical.CodedError(403, "user is an ultra restricted user")
	}

	// Groups are "private channels" like #team-ops
	ctx, cancel = newContext()
	defer cancel()

	groups, err := client.GetGroupsContext(ctx, true)
	if err != nil {
		return nil, errors.Wrap(err, "groups.list")
	}
	groupIDs := make([]string, 0, len(groups)*2)
	for _, g := range groups {
		if !g.IsArchived {
			groupIDs = append(groupIDs, g.ID)
			groupIDs = append(groupIDs, g.Name)
		}
	}

	// UserGroups are mentioned at once like @marketing or @engineering
	ctx, cancel = newContext()
	defer cancel()

	usergroups, err := client.GetUserGroupsContext(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "usergroups.list")
	}
	usergroupIDs := make([]string, 0, len(usergroups)*2)
	for _, u := range usergroups {
		if u.DateDelete == 0 && u.DeletedBy == "" {
			usergroupIDs = append(usergroupIDs, u.ID)
			usergroupIDs = append(usergroupIDs, u.Handle)
		}
	}

	// User is the user corresponding to the token
	userIDs := []string{user.ID, user.Name}

	// Accumulate all policies
	groupPolicies, err := b.GroupsMap.Policies(req.Storage, groupIDs...)
	if err != nil {
		return nil, errors.Wrap(err, "group policies")
	}
	usergroupPolicies, err := b.UsergroupsMap.Policies(req.Storage, usergroupIDs...)
	if err != nil {
		return nil, errors.Wrap(err, "usergroup policies")
	}
	userPolicies, err := b.UsersMap.Policies(req.Storage, userIDs...)
	if err != nil {
		return nil, errors.Wrap(err, "user policies")
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

	// If there are no policies attached, that means we should not issue a token
	if len(policies) == 0 {
		return nil, logical.CodedError(403, "user has no mapped policies")
	}

	// Parse TTLs
	ttl, maxTTL, err := b.SanitizeTTLStr(config.TTL.String(), config.MaxTTL.String())
	if err != nil {
		return nil, errors.Wrap(err, "failed to sanitize TTLs")
	}

	// Return the response
	return &verifyResp{
		policies: policies,
		user:     user,
		team:     team,
		ttl:      ttl,
		maxTTL:   maxTTL,
	}, nil
}
