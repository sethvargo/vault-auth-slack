package slack

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
)

func testBackendEmpty(tb testing.TB) (*backend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = hclog.NewNullLogger()
	config.System = new(logical.StaticSystemView)

	b, err := Factory(context.Background(), config)
	if err != nil {
		tb.Fatal(err)
	}
	return b.(*backend), config.StorageView
}

func testBackendConfigured(tb testing.TB, data map[string]interface{}, config *testServerConfig) (*backend, logical.Storage, func()) {
	tb.Helper()

	address, closer := testServer(tb, config)

	// Override endpoint
	if data == nil {
		data = make(map[string]interface{})
	}
	data["endpoint"] = address

	b, storage := testBackendConfig(tb, data)
	return b, storage, closer

	//"access_token": "xoxp-12345",
	// "teams":        []string{"T12345"},
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
	if err := storage.Put(context.Background(), &logical.StorageEntry{
		Key:   "config",
		Value: data,
	}); err != nil {
		tb.Fatal(err)
	}

	return backend, storage
}

func testMapPolicy(tb testing.TB, b *backend, s logical.Storage, thing, name, policy string) {
	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Storage:   s,
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("map/%s/%s", thing, name),
		Data: map[string]interface{}{
			"policy": policy,
		},
	}); err != nil {
		tb.Fatal(err)
	}
}

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
	return fmt.Sprintf("%s/", ts.URL), func() { ts.Close() }
}
