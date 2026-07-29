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

// Canonical contract:
// @ff/ff_web_server_go/design/session_instance_authcrunch_projection.md

// Session_Instance is the sanitized FF projection of the current authenticated authcrunch browser session.
type Session_Instance struct {
	Mime_Type                     string   `json:"mime_type" xml:"mime_type" yaml:"mime_type"`
	Session_ID                    string   `json:"session_id" xml:"session_id" yaml:"session_id"`
	URI_Template                  string   `json:"uri_template" xml:"uri_template" yaml:"uri_template"`
	URI                           string   `json:"uri" xml:"uri" yaml:"uri"`
	Is_Authenticated              bool     `json:"is_authenticated" xml:"is_authenticated" yaml:"is_authenticated"`
	Identity_ID                   string   `json:"identity_id,omitempty" xml:"identity_id,omitempty" yaml:"identity_id,omitempty"`
	Identity_URI                  string   `json:"identity_uri,omitempty" xml:"identity_uri,omitempty" yaml:"identity_uri,omitempty"`
	User_Name                     string   `json:"user_name,omitempty" xml:"user_name,omitempty" yaml:"user_name,omitempty"`
	User_Contact_Email            string   `json:"user_contact_email,omitempty" xml:"user_contact_email,omitempty" yaml:"user_contact_email,omitempty"`
	Role_List                     []string `json:"role_list,omitempty" xml:"role_list,omitempty" yaml:"role_list,omitempty"`
	Authentication_Realm          string   `json:"authentication_realm,omitempty" xml:"authentication_realm,omitempty" yaml:"authentication_realm,omitempty"`
	Authentication_Method         string   `json:"authentication_method,omitempty" xml:"authentication_method,omitempty" yaml:"authentication_method,omitempty"`
	Created_ISO_8601              string   `json:"created_iso_8601,omitempty" xml:"created_iso_8601,omitempty" yaml:"created_iso_8601,omitempty"`
	Expires_ISO_8601              string   `json:"expires_iso_8601,omitempty" xml:"expires_iso_8601,omitempty" yaml:"expires_iso_8601,omitempty"`
	Session_Duration_MS           int64    `json:"session_duration_ms,omitempty" xml:"session_duration_ms,omitempty" yaml:"session_duration_ms,omitempty"`
	Session_Remaining_Duration_MS int64    `json:"session_remaining_duration_ms,omitempty" xml:"session_remaining_duration_ms,omitempty" yaml:"session_remaining_duration_ms,omitempty"`
}
