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

package fact_bag

import (
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

func Test_Session_Instance_Create(t *testing.T) {
	issued_at := time.Date(2026, 7, 29, 20, 0, 0, 0, time.UTC)
	expires_at := issued_at.Add(time.Hour)
	timestamp_current := issued_at.Add(15 * time.Minute)
	parsed_user, err := user.NewUser(map[string]interface{}{
		"jti": "ff-session-token-id", "sub": "administrator", "name": "Administrator, Local", "email": "administrator@localhost",
		"roles": []string{"authp/user", "authp/admin"}, "iat": issued_at.Unix(), "exp": expires_at.Unix(),
	})
	if err != nil {
		t.Fatalf("user create: %v", err)
	}
	parsed_user.Authenticator = user.Authenticator{Realm: "local", Method: "password"}
	request_record := requests.NewRequest()
	request_record.Upstream.SessionID = "ff-session-test-000000000000000001"
	request_record.Response.Authenticated = true

	session_instance, err := Session_Instance_Create(
		request_record,
		parsed_user,
		"1ae0d114-d319-4220-9c0b-a183f9464f05",
		"identity/instance/1ae0d114-d319-4220-9c0b-a183f9464f05",
		"administrator",
		"administrator@localhost",
		timestamp_current,
	)
	if err != nil {
		t.Fatalf("session instance create: %v", err)
	}
	if session_instance.Mime_Type != "session/instance" {
		t.Fatalf("mime_type is %q", session_instance.Mime_Type)
	}
	if session_instance.URI != "session/instance/ff-session-test-000000000000000001" {
		t.Fatalf("uri is %q", session_instance.URI)
	}
	if session_instance.Identity_URI != "identity/instance/1ae0d114-d319-4220-9c0b-a183f9464f05" {
		t.Fatalf("identity_uri is %q", session_instance.Identity_URI)
	}
	if session_instance.User_Name != "administrator" {
		t.Fatalf("user_name is %q", session_instance.User_Name)
	}
	if session_instance.User_Contact_Email != "administrator@localhost" {
		t.Fatalf("user_contact_email is %q", session_instance.User_Contact_Email)
	}
	if len(session_instance.Role_List) != 2 || session_instance.Role_List[0] != "authp/admin" {
		t.Fatalf("role_list is %#v", session_instance.Role_List)
	}
	if session_instance.Session_Duration_MS != 3600000 {
		t.Fatalf("session_duration_ms is %d", session_instance.Session_Duration_MS)
	}
	if session_instance.Session_Remaining_Duration_MS != 2700000 {
		t.Fatalf("session_remaining_duration_ms is %d", session_instance.Session_Remaining_Duration_MS)
	}
}
