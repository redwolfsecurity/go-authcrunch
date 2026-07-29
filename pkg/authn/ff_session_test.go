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
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/requests"
	session_fact_bag "github.com/greenpau/go-authcrunch/pkg/session/fact_bag"
)

func Test_FF_Session_Read(t *testing.T) {
	portal, administrator_user, _ := ff_identity_test_portal_create(t)
	request_record := requests.NewRequest()
	request_record.Upstream.SessionID = ff_identity_test_session_id
	request_record.Response.Authenticated = true
	timestamp_current := time.Now().UTC()

	current_writer := httptest.NewRecorder()
	if err := portal.ff_session_current_get(current_writer, request_record, administrator_user, timestamp_current); err != nil {
		t.Fatalf("current session get: %v", err)
	}
	var current session_fact_bag.Session_Instance
	if err := json.Unmarshal(current_writer.Body.Bytes(), &current); err != nil {
		t.Fatalf("current session decode: %v", err)
	}
	if current.Mime_Type != "session/instance" {
		t.Fatalf("current session mime_type is %q", current.Mime_Type)
	}
	if current.Session_ID != ff_identity_test_session_id {
		t.Fatalf("current session id is %q", current.Session_ID)
	}
	if !current.Is_Authenticated {
		t.Fatal("current session is not authenticated")
	}
	if current.Identity_URI != "identity/instance/administrator" {
		t.Fatalf("current session identity_uri is %q", current.Identity_URI)
	}
	if current.Expires_ISO_8601 == "" {
		t.Fatal("current session expiry timestamp is absent")
	}

	unauthenticated_request := httptest.NewRequest(http.MethodGet, "/aaa/ff/session/current", nil)
	unauthenticated_writer := httptest.NewRecorder()
	unauthenticated_record := requests.NewRequest()
	if err := portal.ServeHTTP(context.Background(), unauthenticated_writer, unauthenticated_request, unauthenticated_record); err != nil {
		t.Fatalf("unauthenticated FF session request: %v", err)
	}
	if unauthenticated_writer.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status is %d, want %d", unauthenticated_writer.Code, http.StatusUnauthorized)
	}
}
