package slack

import (
	"context"
	"reflect"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestBackend_login(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		config    map[string]interface{}
		server    *testServerConfig
		mapPolicy []string
		err       error
	}{
		{
			name:   "auth_invalid",
			server: &testServerConfig{authInvalid: true},
			err:    logical.ErrPermissionDenied,
		},
		{
			name:   "no_teams",
			config: map[string]interface{}{"teams": []string{}},
			err:    logical.CodedError(403, "user is not part of any registered teams"),
		},
		{
			name:   "groups_invalid",
			config: map[string]interface{}{"teams": []string{"T12345"}},
			server: &testServerConfig{groupsInvalid: true},
			err:    logical.ErrPermissionDenied,
		},
		{
			name:      "groups_is_archived",
			config:    map[string]interface{}{"teams": []string{"T12345"}},
			mapPolicy: []string{"groups", "G12345", "my-group-policy"},
			server:    &testServerConfig{groupsIsArchived: true},
			err:       logical.CodedError(403, "user has no mapped policies"),
		},
		{
			name:   "usergroups_invalid",
			config: map[string]interface{}{"teams": []string{"T12345"}},
			server: &testServerConfig{usergroupsInvalid: true},
			err:    logical.ErrPermissionDenied,
		},
		{
			name:      "usergroups_date_delete",
			config:    map[string]interface{}{"teams": []string{"T12345"}},
			mapPolicy: []string{"usergroups", "S12345", "my-usergroup-policy"},
			server:    &testServerConfig{usergroupsDateDelete: 12890321},
			err:       logical.CodedError(403, "user has no mapped policies"),
		},
		{
			name:   "user_invalid",
			config: map[string]interface{}{"teams": []string{"T12345"}},
			server: &testServerConfig{userInvalid: true},
			err:    logical.ErrPermissionDenied,
		},
		{
			name:      "user_restricted",
			config:    map[string]interface{}{"teams": []string{"T12345"}},
			mapPolicy: []string{"users", "U12345", "my-user-policy"},
			server:    &testServerConfig{userIsRestricted: true},
			err:       logical.CodedError(403, "user is a restricted user"),
		},
		{
			name: "user_restricted_allowed",
			config: map[string]interface{}{
				"allow_restricted_users": true,
				"teams":                  []string{"T12345"},
			},
			mapPolicy: []string{"users", "U12345", "my-user-policy"},
			server:    &testServerConfig{userIsRestricted: true},
		},
		{
			name:      "user_ultra_restricted",
			config:    map[string]interface{}{"teams": []string{"T12345"}},
			mapPolicy: []string{"users", "U12345", "my-user-policy"},
			server:    &testServerConfig{userIsUltraRestricted: true},
			err:       logical.CodedError(403, "user is an ultra restricted user"),
		},
		{
			name: "user_ultra_restricted_allowed",
			config: map[string]interface{}{
				"allow_ultra_restricted_users": true,
				"teams":                        []string{"T12345"},
			},
			mapPolicy: []string{"users", "U12345", "my-user-policy"},
			server:    &testServerConfig{userIsUltraRestricted: true},
		},
		{
			name:      "user_bot",
			config:    map[string]interface{}{"teams": []string{"T12345"}},
			mapPolicy: []string{"users", "U12345", "my-user-policy"},
			server:    &testServerConfig{userIsBot: true},
			err:       logical.CodedError(403, "user is a bot"),
		},
		{
			name: "user_bot_allowed",
			config: map[string]interface{}{
				"allow_bot_users": true,
				"teams":           []string{"T12345"},
			},
			mapPolicy: []string{"users", "U12345", "my-user-policy"},
			server:    &testServerConfig{userIsBot: true},
		},
		{
			name:      "user_is_deleted",
			config:    map[string]interface{}{"teams": []string{"T12345"}},
			mapPolicy: []string{"users", "U12345", "my-user-policy"},
			server:    &testServerConfig{userIsDeleted: true},
			err:       logical.CodedError(403, "user is deleted"),
		},
		{
			name:      "user_no_2fa",
			config:    map[string]interface{}{"teams": []string{"T12345"}},
			mapPolicy: []string{"users", "U12345", "my-user-policy"},
			server:    &testServerConfig{userNo2FA: true},
			err:       logical.CodedError(403, "user does not have 2FA enabled"),
		},
		{
			name: "user_no_2fa_allowed",
			config: map[string]interface{}{
				"allow_non_2fa": true,
				"teams":         []string{"T12345"},
			},
			mapPolicy: []string{"users", "U12345", "my-user-policy"},
			server:    &testServerConfig{userNo2FA: true},
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			b, s, closer := testBackendConfigured(t, tc.config, tc.server)
			defer closer()

			// Mapp any user-supplied policies
			if p := tc.mapPolicy; len(p) == 3 {
				testMapPolicy(t, b, s, p[0], p[1], p[2])
			}

			resp, err := b.HandleRequest(ctx, &logical.Request{
				Storage:   s,
				Operation: logical.UpdateOperation,
				Path:      "login/token",
				Data: map[string]interface{}{
					"token": "xoxp-12345",
				},
			})

			if !reflect.DeepEqual(err, tc.err) {
				t.Errorf("expected %#v to be %#v", err, tc.err)
			}

			if err == nil {
				if d := resp.Auth.DisplayName; d == "" {
					t.Errorf("bad display name: %q", d)
				}
			}
		})
	}
}
