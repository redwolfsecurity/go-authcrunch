// Copyright 2026 RedWolf Security Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authn

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/role"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	identity_fact_bag "github.com/greenpau/go-authcrunch/pkg/identity/fact_bag"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	logutil "github.com/greenpau/go-authcrunch/pkg/util/log"
)

const ff_identity_test_session_id = "ff-identity-test-session-000000000001"

func Test_FF_Identity_Read(t *testing.T) {
	portal, administrator_user, regular_user := ff_identity_test_portal_create(t)
	if err := portal.sessions.Add(ff_identity_test_session_id, administrator_user); err != nil {
		t.Fatalf("administrator session add: %v", err)
	}
	parsed_user := administrator_user.Clone()
	request_record := requests.NewRequest()
	request_record.Response.Authenticated = true

	current_writer := httptest.NewRecorder()
	if err := portal.ff_identity_current_get(current_writer, request_record, parsed_user); err != nil {
		t.Fatalf("current identity get: %v", err)
	}
	var current identity_fact_bag.Identity_Instance
	if err := json.Unmarshal(current_writer.Body.Bytes(), &current); err != nil {
		t.Fatalf("current identity decode: %v", err)
	}
	if current.User_Name != "administrator" {
		t.Fatalf("current identity username is %q", current.User_Name)
	}
	if len(current.Role_List) != 2 || current.Role_List[0] != "authp/admin" {
		t.Fatalf("administrator roles are missing: %#v", current.Role_List)
	}

	list_writer := httptest.NewRecorder()
	if err := portal.ff_identity_list_get(list_writer, requests.NewRequest(), parsed_user); err != nil {
		t.Fatalf("identity list get: %v", err)
	}
	var identity_list []identity_fact_bag.Identity_Instance
	if err := json.Unmarshal(list_writer.Body.Bytes(), &identity_list); err != nil {
		t.Fatalf("identity list decode: %v", err)
	}
	if len(identity_list) != 2 {
		t.Fatalf("identity list count is %d, want 2", len(identity_list))
	}
	identity_by_user_name := make(map[string]identity_fact_bag.Identity_Instance)
	for _, identity_instance := range identity_list {
		identity_by_user_name[identity_instance.User_Name] = identity_instance
	}
	if _, exists := identity_by_user_name["administrator"]; !exists {
		t.Fatal("administrator identity is absent")
	}
	if _, exists := identity_by_user_name["user"]; !exists {
		t.Fatal("user identity is absent")
	}
	if err := portal.authorizedRole(regular_user, []role.Kind{role.Admin}, true); err == nil {
		t.Fatal("regular user unexpectedly satisfied administrator role")
	}

	unauthenticated_request := httptest.NewRequest(http.MethodGet, "/aaa/ff/identity/current", nil)
	unauthenticated_writer := httptest.NewRecorder()
	unauthenticated_record := requests.NewRequest()
	if err := portal.ServeHTTP(context.Background(), unauthenticated_writer, unauthenticated_request, unauthenticated_record); err != nil {
		t.Fatalf("unauthenticated FF identity request: %v", err)
	}
	if unauthenticated_writer.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status is %d, want %d", unauthenticated_writer.Code, http.StatusUnauthorized)
	}
}

func ff_identity_test_portal_create(t *testing.T) (*Portal, *user.User, *user.User) {
	t.Helper()
	database_path := filepath.Join(t.TempDir(), "identity_store_local.json")
	database, err := identity.NewDatabase(database_path)
	if err != nil {
		t.Fatalf("identity database create: %v", err)
	}
	for _, user_definition := range []requests.User{
		{Username: "administrator", Email: "administrator@localhost", Password: "AAaa11!!0123456789", FullName: "Local Administrator", Roles: []string{"authp/admin", "authp/user"}},
		{Username: "user", Email: "user@localhost", Password: "BBbb22!!0123456789", FullName: "Local User", Roles: []string{"authp/user"}},
	} {
		if err := database.AddUser(&requests.Request{User: user_definition}); err != nil {
			t.Fatalf("identity add %s: %v", user_definition.Username, err)
		}
	}

	logger := logutil.NewLogger()
	identity_store, err := ids.NewIdentityStore(&ids.IdentityStoreConfig{
		Name: "identity_store_local", Kind: "local",
		Params: map[string]interface{}{"path": database_path, "realm": "local"},
	}, logger)
	if err != nil {
		t.Fatalf("identity store create: %v", err)
	}
	if err := identity_store.Configure(); err != nil {
		t.Fatalf("identity store configure: %v", err)
	}
	portal, err := NewPortal(PortalParameters{
		Config: &PortalConfig{
			Name: "authentication_local", CookieConfig: cookie.NewConfig(), IdentityStores: []string{"identity_store_local"},
			API: &APIConfig{ProfileEnabled: true, AdminEnabled: true},
		},
		Logger: logger, IdentityStores: []ids.IdentityStore{identity_store},
	})
	if err != nil {
		t.Fatalf("portal create: %v", err)
	}
	administrator_user := ff_identity_test_session_user_create(t, "administrator", "administrator@localhost", []string{"authp/admin", "authp/user"})
	regular_user := ff_identity_test_session_user_create(t, "user", "user@localhost", []string{"authp/user"})
	return portal, administrator_user, regular_user
}

func ff_identity_test_session_user_create(t *testing.T, user_name string, user_contact_email string, role_list []string) *user.User {
	t.Helper()
	result, err := user.NewUser(map[string]interface{}{
		"jti": ff_identity_test_session_id, "sub": user_name, "email": user_contact_email,
		"roles": role_list, "exp": time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("session user create: %v", err)
	}
	result.Authenticator = user.Authenticator{Name: "identity_store_local", Realm: "local", Method: "local"}
	result.Authorized = true
	return result
}
