package slack

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/vault/logical"
	"github.com/nlopes/slack"
)

type testServerConfig struct {
	authInvalid bool

	groupsInvalid    bool
	groupsIsArchived bool

	usergroupsInvalid    bool
	usergroupsDateDelete int
	usergroupsDeletedBy  string

	userInvalid           bool
	userIsDeleted         bool
	userIsRestricted      bool
	userIsUltraRestricted bool
	userIsBot             bool
	userNo2FA             bool
}

func testServer(tb testing.TB, config *testServerConfig) (string, func()) {
	if config == nil {
		config = &testServerConfig{}
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/auth.test", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")

		if config.authInvalid {
			w.WriteHeader(403)
			w.Write([]byte(`{"error": "invalid_auth"}`))
			return
		}

		if err := r.ParseForm(); err != nil {
			tb.Fatal(err)
		}

		w.WriteHeader(200)
		w.Write([]byte(`{
      "ok": true,
      "url": "https://testteam.slack.com/",
      "team": "testteam",
      "team_id": "T12345",
      "user": "testuser",
      "user_id": "U12345"
    }`))
	})

	mux.HandleFunc("/groups.list", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")

		if config.groupsInvalid {
			w.WriteHeader(403)
			w.Write([]byte(`{"error": "not_authed"}`))
			return
		}

		w.WriteHeader(200)
		w.Write([]byte(fmt.Sprintf(`{
      "ok": true,
      "groups": [
        {
          "id": "G12345",
          "name": "testgroup",
          "is_archived": %t,
          "members": [
            "U12345"
          ]
        }
      ]
    }`, config.groupsIsArchived)))
	})

	mux.HandleFunc("/usergroups.list", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")

		if config.usergroupsInvalid {
			w.WriteHeader(403)
			w.Write([]byte(`{"error": "not_authed"}`))
			return
		}

		w.WriteHeader(200)
		w.Write([]byte(fmt.Sprintf(`{
      "ok": true,
      "usergroups": [
        {
          "id": "S12345",
          "team_id": "T12345",
          "handle": "testusergroup",
          "date_delete": %d,
          "deleted_by": "%s",
          "members": [
            "U12345"
          ]
        }
      ]
    }`, config.usergroupsDateDelete, config.usergroupsDeletedBy)))
	})

	mux.HandleFunc("/users.info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")

		if config.userInvalid {
			w.WriteHeader(403)
			w.Write([]byte(`{"error": "user_not_found"}`))
			return
		}

		w.WriteHeader(200)
		w.Write([]byte(fmt.Sprintf(`{
      "ok": true,
      "user": {
        "id": "U12345",
        "team_id": "T12345",
        "name": "testuser",
        "deleted": %t,
        "real_name": "Test User",
        "is_restricted": %t,
        "is_ultra_restricted": %t,
        "is_bot": %t,
        "has_2fa": %t
      }
    }`,
			config.userIsDeleted,
			config.userIsRestricted,
			config.userIsUltraRestricted,
			config.userIsBot,
			!config.userNo2FA,
		)))
	})

	ts := httptest.NewServer(mux)
	return ts.URL + "/", func() { ts.Close() }
}

func testBackendEmpty(tb testing.TB) (*backend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	b, err := Factory(config)
	if err != nil {
		tb.Fatal(err)
	}

	return b.(*backend), config.StorageView
}

func testBackendConfigured(tb testing.TB) (*backend, logical.Storage) {
	tb.Helper()

	return testBackendConfig(tb, map[string]interface{}{
		"access_token": "xoxp-12345",
		"teams":        []string{"T12345"},
	})
}

func testBackendConfig(tb testing.TB, config map[string]interface{}) (*backend, logical.Storage) {
	tb.Helper()

	// Create the JSON
	data, err := json.Marshal(config)
	if err != nil {
		tb.Fatal(err)
	}

	// Create the backend
	backend, storage := testBackendEmpty(tb)
	storage.Put(&logical.StorageEntry{
		Key:   "config",
		Value: data,
	})

	return backend, storage
}

func testMapPolicy(tb testing.TB, b *backend, s logical.Storage, thing, name, policy string) {
	b.HandleRequest(&logical.Request{
		Storage:   s,
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("map/%s/%s", thing, name),
		Data: map[string]interface{}{
			"policy": policy,
		},
	})
}

func testExpectVaultCodedError(tb testing.TB, resp *logical.Response, err error, exp string) {
	tb.Helper()

	errTyp, ok := err.(logical.HTTPCodedError)
	if !ok {
		tb.Fatalf("not HTTPCodedError: %T: %#v", errTyp, resp)
	}

	if errTyp.Code() != 403 {
		tb.Errorf("expected %d to be %d: %v", errTyp.Code(), 403, resp)
	}

	if !strings.Contains(errTyp.Error(), exp) {
		tb.Errorf("expected %q to contain %q: %v", errTyp.Error(), exp, resp)
	}
}

func TestBackend_loginToken(t *testing.T) {
	t.Run("no_config", func(t *testing.T) {
		b, storage := testBackendEmpty(t)

		address, closer := testServer(t, nil)
		defer closer()

		slack.SLACK_API = address

		resp, err := b.HandleRequest(&logical.Request{
			Storage:   storage,
			Operation: logical.ReadOperation,
			Path:      "config",
		})
		if err == nil {
			t.Errorf("expected error: %v", resp)
		}
	})

	t.Run("auth_invalid", func(t *testing.T) {
		b, storage := testBackendConfigured(t)

		address, closer := testServer(t, &testServerConfig{
			authInvalid: true,
		})
		defer closer()

		slack.SLACK_API = address

		resp, err := b.HandleRequest(&logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "login/token",
			Data: map[string]interface{}{
				"token": "xoxp-12345",
			},
		})
		if err != logical.ErrPermissionDenied {
			t.Errorf("expected %v to be %v: %v", err, logical.ErrPermissionDenied, resp)
		}
	})

	t.Run("no_teams", func(t *testing.T) {
		b, storage := testBackendConfig(t, map[string]interface{}{
			"teams": []string{},
		})

		address, closer := testServer(t, nil)
		defer closer()

		slack.SLACK_API = address

		resp, err := b.HandleRequest(&logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "login/token",
			Data: map[string]interface{}{
				"token": "xoxp-12345",
			},
		})
		testExpectVaultCodedError(t, resp, err, "user is not part of any registered teams")
	})

	t.Run("groups_invalid", func(t *testing.T) {
		b, storage := testBackendConfigured(t)

		address, closer := testServer(t, &testServerConfig{
			groupsInvalid: true,
		})
		defer closer()

		slack.SLACK_API = address

		resp, err := b.HandleRequest(&logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "login/token",
			Data: map[string]interface{}{
				"token": "xoxp-12345",
			},
		})
		if err != logical.ErrPermissionDenied {
			t.Errorf("expected %v to be %v: %v", err, logical.ErrPermissionDenied, resp)
		}
	})

	t.Run("groups_is_archived", func(t *testing.T) {
		b, storage := testBackendConfig(t, map[string]interface{}{
			"teams": []string{"T12345"},
		})

		testMapPolicy(t, b, storage, "groups", "G12345", "my-group-policy")

		address, closer := testServer(t, &testServerConfig{
			groupsIsArchived: true,
		})
		defer closer()

		slack.SLACK_API = address

		resp, err := b.HandleRequest(&logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "login/token",
			Data: map[string]interface{}{
				"token": "xoxp-12345",
			},
		})
		testExpectVaultCodedError(t, resp, err, "user has no mapped policies")
	})

	t.Run("usergroups_invalid", func(t *testing.T) {
		b, storage := testBackendConfigured(t)

		address, closer := testServer(t, &testServerConfig{
			usergroupsInvalid: true,
		})
		defer closer()

		slack.SLACK_API = address

		resp, err := b.HandleRequest(&logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "login/token",
			Data: map[string]interface{}{
				"token": "xoxp-12345",
			},
		})
		if err != logical.ErrPermissionDenied {
			t.Errorf("expected %v to be %v: %v", err, logical.ErrPermissionDenied, resp)
		}
	})

	t.Run("usergroups_date_delete", func(t *testing.T) {
		b, storage := testBackendConfig(t, map[string]interface{}{
			"teams": []string{"T12345"},
		})

		testMapPolicy(t, b, storage, "usergroups", "S12345", "my-usergroup-policy")

		address, closer := testServer(t, &testServerConfig{
			usergroupsDateDelete: 12890321,
		})
		defer closer()

		slack.SLACK_API = address

		resp, err := b.HandleRequest(&logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "login/token",
			Data: map[string]interface{}{
				"token": "xoxp-12345",
			},
		})
		testExpectVaultCodedError(t, resp, err, "user has no mapped policies")
	})

	t.Run("usergroups_deleted_by", func(t *testing.T) {
		b, storage := testBackendConfig(t, map[string]interface{}{
			"teams": []string{"T12345"},
		})

		testMapPolicy(t, b, storage, "usergroups", "S12345", "my-usergroup-policy")

		address, closer := testServer(t, &testServerConfig{
			usergroupsDeletedBy: "sethvargo",
		})
		defer closer()

		slack.SLACK_API = address

		resp, err := b.HandleRequest(&logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "login/token",
			Data: map[string]interface{}{
				"token": "xoxp-12345",
			},
		})
		testExpectVaultCodedError(t, resp, err, "user has no mapped policies")
	})

	t.Run("user_invalid", func(t *testing.T) {
		b, storage := testBackendConfigured(t)

		address, closer := testServer(t, &testServerConfig{
			userInvalid: true,
		})
		defer closer()

		slack.SLACK_API = address

		resp, err := b.HandleRequest(&logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "login/token",
			Data: map[string]interface{}{
				"token": "xoxp-12345",
			},
		})
		if err != logical.ErrPermissionDenied {
			t.Errorf("expected %v to be %v: %v", err, logical.ErrPermissionDenied, resp)
		}
	})

	t.Run("user_is_restricted", func(t *testing.T) {
		b, storage := testBackendConfig(t, map[string]interface{}{
			"teams": []string{"T12345"},
		})

		testMapPolicy(t, b, storage, "users", "U12345", "my-user-policy")

		address, closer := testServer(t, &testServerConfig{
			userIsRestricted: true,
		})
		defer closer()

		slack.SLACK_API = address

		resp, err := b.HandleRequest(&logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "login/token",
			Data: map[string]interface{}{
				"token": "xoxp-12345",
			},
		})
		testExpectVaultCodedError(t, resp, err, "user is a restricted user")
	})

	t.Run("user_is_restricted_allow", func(t *testing.T) {
		b, storage := testBackendConfig(t, map[string]interface{}{
			"teams":                  []string{"T12345"},
			"allow_restricted_users": true,
		})

		testMapPolicy(t, b, storage, "users", "U12345", "my-user-policy")

		address, closer := testServer(t, &testServerConfig{
			userIsRestricted: true,
		})
		defer closer()

		slack.SLACK_API = address

		resp, err := b.HandleRequest(&logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "login/token",
			Data: map[string]interface{}{
				"token": "xoxp-12345",
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		if exp, act := "testuser", resp.Auth.DisplayName; exp != act {
			t.Errorf("expected %q to be %q", exp, act)
		}
	})

	t.Run("user_is_ultra_restricted", func(t *testing.T) {
		b, storage := testBackendConfig(t, map[string]interface{}{
			"teams": []string{"T12345"},
		})

		testMapPolicy(t, b, storage, "users", "U12345", "my-user-policy")

		address, closer := testServer(t, &testServerConfig{
			userIsUltraRestricted: true,
		})
		defer closer()

		slack.SLACK_API = address

		resp, err := b.HandleRequest(&logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "login/token",
			Data: map[string]interface{}{
				"token": "xoxp-12345",
			},
		})
		testExpectVaultCodedError(t, resp, err, "user is an ultra restricted user")
	})

	t.Run("user_is_ultra_restricted_allow", func(t *testing.T) {
		b, storage := testBackendConfig(t, map[string]interface{}{
			"teams": []string{"T12345"},
			"allow_ultra_restricted_users": true,
		})

		testMapPolicy(t, b, storage, "users", "U12345", "my-user-policy")

		address, closer := testServer(t, &testServerConfig{
			userIsUltraRestricted: true,
		})
		defer closer()

		slack.SLACK_API = address

		resp, err := b.HandleRequest(&logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "login/token",
			Data: map[string]interface{}{
				"token": "xoxp-12345",
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		if exp, act := "testuser", resp.Auth.DisplayName; exp != act {
			t.Errorf("expected %q to be %q", exp, act)
		}
	})

	t.Run("user_is_bot", func(t *testing.T) {
		b, storage := testBackendConfig(t, map[string]interface{}{
			"teams": []string{"T12345"},
		})

		testMapPolicy(t, b, storage, "users", "U12345", "my-user-policy")

		address, closer := testServer(t, &testServerConfig{
			userIsBot: true,
		})
		defer closer()

		slack.SLACK_API = address

		resp, err := b.HandleRequest(&logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "login/token",
			Data: map[string]interface{}{
				"token": "xoxp-12345",
			},
		})
		testExpectVaultCodedError(t, resp, err, "user is a bot")
	})

	t.Run("user_is_bot_allow", func(t *testing.T) {
		b, storage := testBackendConfig(t, map[string]interface{}{
			"teams":           []string{"T12345"},
			"allow_bot_users": true,
		})

		testMapPolicy(t, b, storage, "users", "U12345", "my-user-policy")

		address, closer := testServer(t, &testServerConfig{
			userIsBot: true,
		})
		defer closer()

		slack.SLACK_API = address

		resp, err := b.HandleRequest(&logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "login/token",
			Data: map[string]interface{}{
				"token": "xoxp-12345",
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		if exp, act := "testuser", resp.Auth.DisplayName; exp != act {
			t.Errorf("expected %q to be %q", exp, act)
		}
	})

	t.Run("user_is_deleted", func(t *testing.T) {
		b, storage := testBackendConfig(t, map[string]interface{}{
			"teams": []string{"T12345"},
		})

		testMapPolicy(t, b, storage, "users", "U12345", "my-user-policy")

		address, closer := testServer(t, &testServerConfig{
			userIsDeleted: true,
		})
		defer closer()

		slack.SLACK_API = address

		resp, err := b.HandleRequest(&logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "login/token",
			Data: map[string]interface{}{
				"token": "xoxp-12345",
			},
		})
		testExpectVaultCodedError(t, resp, err, "user is deleted")
	})

	t.Run("user_no_2fa", func(t *testing.T) {
		b, storage := testBackendConfig(t, map[string]interface{}{
			"teams": []string{"T12345"},
		})

		testMapPolicy(t, b, storage, "users", "U12345", "my-user-policy")

		address, closer := testServer(t, &testServerConfig{
			userNo2FA: true,
		})
		defer closer()

		slack.SLACK_API = address

		resp, err := b.HandleRequest(&logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "login/token",
			Data: map[string]interface{}{
				"token": "xoxp-12345",
			},
		})
		testExpectVaultCodedError(t, resp, err, "user does not have 2FA enabled")
	})

	t.Run("user_no_2fa_allow", func(t *testing.T) {
		b, storage := testBackendConfig(t, map[string]interface{}{
			"teams":         []string{"T12345"},
			"allow_non_2fa": true,
		})

		testMapPolicy(t, b, storage, "users", "U12345", "my-user-policy")

		address, closer := testServer(t, &testServerConfig{
			userNo2FA: true,
		})
		defer closer()

		slack.SLACK_API = address

		resp, err := b.HandleRequest(&logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "login/token",
			Data: map[string]interface{}{
				"token": "xoxp-12345",
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		if exp, act := "testuser", resp.Auth.DisplayName; exp != act {
			t.Errorf("expected %q to be %q", exp, act)
		}
	})

	t.Run("multipolicy", func(t *testing.T) {
		b, storage := testBackendConfig(t, map[string]interface{}{
			"teams": []string{"T12345"},
		})

		testMapPolicy(t, b, storage, "groups", "G12345", "my-group-policy")
		testMapPolicy(t, b, storage, "usergroups", "S12345", "my-usergroup-policy")
		testMapPolicy(t, b, storage, "users", "U12345", "my-user-policy")

		address, closer := testServer(t, nil)
		defer closer()

		slack.SLACK_API = address

		resp, err := b.HandleRequest(&logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "login/token",
			Data: map[string]interface{}{
				"token": "xoxp-12345",
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		exp := []string{
			"my-group-policy",
			"my-usergroup-policy",
			"my-user-policy",
		}
		sort.Strings(exp)
		act := resp.Auth.Policies
		sort.Strings(act)
		if !reflect.DeepEqual(exp, act) {
			t.Errorf("expected %v to be %v", exp, act)
		}
	})

	t.Run("names_instead_of_ids", func(t *testing.T) {
		b, storage := testBackendConfig(t, map[string]interface{}{
			"teams": []string{"T12345"},
		})

		testMapPolicy(t, b, storage, "groups", "testgroup", "my-group-policy")
		testMapPolicy(t, b, storage, "usergroups", "testusergroup", "my-usergroup-policy")
		testMapPolicy(t, b, storage, "users", "testuser", "my-user-policy")

		address, closer := testServer(t, nil)
		defer closer()

		slack.SLACK_API = address

		resp, err := b.HandleRequest(&logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "login/token",
			Data: map[string]interface{}{
				"token": "xoxp-12345",
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		exp := []string{
			"my-group-policy",
			"my-usergroup-policy",
			"my-user-policy",
		}
		sort.Strings(exp)
		act := resp.Auth.Policies
		sort.Strings(act)
		if !reflect.DeepEqual(exp, act) {
			t.Errorf("expected %v to be %v", exp, act)
		}
	})

	t.Run("token_metadata", func(t *testing.T) {
		b, storage := testBackendConfig(t, map[string]interface{}{
			"teams": []string{"T12345"},
		})

		testMapPolicy(t, b, storage, "users", "U12345", "my-user-policy")

		address, closer := testServer(t, nil)
		defer closer()

		slack.SLACK_API = address

		resp, err := b.HandleRequest(&logical.Request{
			Storage:   storage,
			Operation: logical.UpdateOperation,
			Path:      "login/token",
			Data: map[string]interface{}{
				"token": "xoxp-12345",
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		if exp, act := "testuser", resp.Auth.DisplayName; exp != act {
			t.Errorf("expected %q to be %q", exp, act)
		}
		if exp, act := []string{"my-user-policy"}, resp.Auth.Policies; !reflect.DeepEqual(exp, act) {
			t.Errorf("expected %v to be %v", exp, act)
		}
		if exp, act := "T12345", resp.Auth.Metadata["slack_team_id"]; exp != act {
			t.Errorf("expected %q to be %q", exp, act)
		}
		if exp, act := "testteam", resp.Auth.Metadata["slack_team_name"]; exp != act {
			t.Errorf("expected %q to be %q", exp, act)
		}
		if exp, act := "U12345", resp.Auth.Metadata["slack_user_id"]; exp != act {
			t.Errorf("expected %q to be %q", exp, act)
		}
		if exp, act := "testuser", resp.Auth.Metadata["slack_user_name"]; exp != act {
			t.Errorf("expected %q to be %q", exp, act)
		}
		if exp, act := "Test User", resp.Auth.Metadata["slack_user_real_name"]; exp != act {
			t.Errorf("expected %q to be %q", exp, act)
		}
	})
}
