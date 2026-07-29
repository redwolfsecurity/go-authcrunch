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
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

const (
	session_instance_mime_type  = "session/instance"
	identity_instance_mime_type = "identity/instance"
)

// Session_Instance_Create projects one authenticated authcrunch request into a sanitized FF session fact bag.
func Session_Instance_Create(request_record *requests.Request, parsed_user *user.User, timestamp_current time.Time) (*Session_Instance, error) {
	if request_record == nil {
		return nil, errors.New("session request record is nil")
	}
	if parsed_user == nil || parsed_user.Claims == nil {
		return nil, errors.New("authenticated session user claims are unavailable")
	}
	if !request_record.Response.Authenticated {
		return nil, errors.New("session request is not authenticated")
	}
	session_id := strings.TrimSpace(request_record.Upstream.SessionID)
	if session_id == "" {
		return nil, errors.New("session id is empty")
	}
	identity_id := strings.TrimSpace(parsed_user.Claims.Subject)
	if identity_id == "" {
		return nil, errors.New("session identity id is empty")
	}
	if timestamp_current.IsZero() {
		timestamp_current = time.Now().UTC()
	}
	timestamp_current = timestamp_current.UTC()

	issued_at := timestamp_from_epoch_second(parsed_user.Claims.IssuedAt)
	expires_at := timestamp_from_epoch_second(parsed_user.Claims.ExpiresAt)

	result := &Session_Instance{
		Mime_Type:        session_instance_mime_type,
		Session_ID:       session_id,
		URI_Template:     "[mime_type]/[session_id]",
		URI:              fact_bag_uri_create(session_instance_mime_type, session_id),
		Is_Authenticated: true,
		Identity_ID:      identity_id,
		Identity_URI:     fact_bag_uri_create(identity_instance_mime_type, identity_id),
	}

	if user_name := strings.TrimSpace(parsed_user.Claims.Name); user_name != "" {
		result.User_Name = user_name
	} else {
		result.User_Name = identity_id
	}
	result.User_Contact_Email = strings.TrimSpace(parsed_user.Claims.Email)
	result.Role_List = string_list_nonempty_create(parsed_user.Claims.Roles)
	sort.Strings(result.Role_List)
	result.Authentication_Realm = strings.TrimSpace(parsed_user.Authenticator.Realm)
	result.Authentication_Method = strings.TrimSpace(parsed_user.Authenticator.Method)
	if !issued_at.IsZero() {
		result.Created_ISO_8601 = timestamp_iso_8601_create(issued_at)
	}
	if !expires_at.IsZero() {
		result.Expires_ISO_8601 = timestamp_iso_8601_create(expires_at)
	}
	if !issued_at.IsZero() && !expires_at.IsZero() && expires_at.After(issued_at) {
		result.Session_Duration_MS = expires_at.Sub(issued_at).Milliseconds()
	}
	if !expires_at.IsZero() {
		remaining_duration_ms := expires_at.Sub(timestamp_current).Milliseconds()
		if remaining_duration_ms > 0 {
			result.Session_Remaining_Duration_MS = remaining_duration_ms
		}
	}

	return result, nil
}

func fact_bag_uri_create(part_list ...string) string {
	return strings.Join(part_list, "/")
}

func timestamp_from_epoch_second(value int64) time.Time {
	if value <= 0 {
		return time.Time{}
	}
	return time.Unix(value, 0).UTC()
}

func timestamp_iso_8601_create(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func string_list_nonempty_create(source []string) []string {
	result := make([]string, 0, len(source))
	for _, value := range source {
		value = strings.TrimSpace(value)
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}
