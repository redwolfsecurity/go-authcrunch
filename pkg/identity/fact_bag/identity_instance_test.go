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
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/identity"
)

func Test_Identity_Instance_Create(t *testing.T) {
	timestamp := time.Date(2026, time.July, 22, 13, 47, 4, 619353000, time.UTC)
	source := &identity.User{
		ID: "1ae0d114-d319-4220-9c0b-a183f9464f05", Human: true, Username: "administrator", Title: "System Administrator",
		Name:          &identity.Name{First: "Local", Middle: "Anthony", Last: "Administrator", Preferred: "Admin", Primary: true, Legal: true, Confirmed: true},
		Names:         []*identity.Name{{First: "Local", Middle: "Anthony", Last: "Administrator", Preferred: "Admin", Primary: true, Legal: true, Confirmed: true}},
		Organization:  &identity.Organization{ID: 7, Name: "provider_organization", Aliases: []string{"provider_alias"}},
		StreetAddress: []*identity.Location{{Street: "100 Example Street", City: "Toronto", State: "Ontario", ZipCode: "M5V 1A1", Current: true}},
		EmailAddress:  &identity.EmailAddress{Address: "administrator@localhost", Domain: "localhost", Confirmed: true},
		Passwords:     []*identity.Password{{Purpose: "generic", Algorithm: "bcrypt", Cost: 12, Hash: "password-hash-must-not-escape", CreatedAt: timestamp}},
		PublicKeys:    []*identity.PublicKey{{ID: "public-key-1", Usage: "ssh", Type: "ed25519", Fingerprint: "SHA256:example", Payload: "public-key-payload-must-not-escape", CreatedAt: timestamp}},
		APIKeys:       []*identity.APIKey{{ID: "api-key-1", Prefix: "ff_local", Usage: "api", Payload: "api-key-payload-must-not-escape", CreatedAt: timestamp}},
		MfaTokens:     []*identity.MfaToken{{ID: "mfa-token-1", Type: "totp", Algorithm: "sha1", Secret: "mfa-secret-must-not-escape", Period: 30, Digits: 6, CreatedAt: timestamp}},
		Lockout:       &identity.LockoutState{}, MfaFailedAttempts: 0,
		Avatar:  &identity.Image{Title: "Administrator", Path: "/aaa/assets/images/administrator.png", Body: "avatar-body-must-not-escape"},
		Created: timestamp, LastModified: timestamp, Revision: 2,
		Roles:              []*identity.Role{{Organization: "authp", Name: "admin"}, {Organization: "authp", Name: "user"}},
		AuthChallengeRules: []string{"mfa"},
		Registration:       &identity.Registration{ID: "registration-1", CreatedAt: timestamp, ApprovedAt: timestamp, Approved: true},
	}

	result, err := Identity_Instance_Create(source)
	if err != nil {
		t.Fatalf("identity instance create: %v", err)
	}
	if result.Mime_Type != "identity/instance" || result.User_Name != "administrator" {
		t.Fatalf("unexpected identity projection: %#v", result)
	}
	if len(result.Name_List) != 1 {
		t.Fatalf("duplicate primary name was not removed: %#v", result.Name_List)
	}
	if strings.Join(result.Role_List, " ") != "authp/admin authp/user" {
		t.Fatalf("roles were not preserved: %#v", result.Role_List)
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("identity instance encode: %v", err)
	}
	for _, refused_value := range []string{
		"password-hash-must-not-escape",
		"public-key-payload-must-not-escape",
		"api-key-payload-must-not-escape",
		"mfa-secret-must-not-escape",
		"avatar-body-must-not-escape",
	} {
		if strings.Contains(string(encoded), refused_value) {
			t.Fatalf("sensitive or refused value escaped projection: %s", refused_value)
		}
	}

	var fact_bag any
	if err := json.Unmarshal(encoded, &fact_bag); err != nil {
		t.Fatalf("identity instance decode: %v", err)
	}
	fact_bag_uri_template_validate(t, fact_bag)
}

func fact_bag_uri_template_validate(t *testing.T, value any) {
	t.Helper()
	switch current := value.(type) {
	case map[string]any:
		if template, valid := current["uri_template"].(string); valid {
			uri, uri_valid := current["uri"].(string)
			if !uri_valid {
				t.Fatalf("object with uri_template has no uri: %#v", current)
			}
			expression_pattern := regexp.MustCompile(`\[([a-z0-9_]+)\]`)
			materialized := expression_pattern.ReplaceAllStringFunc(template, func(expression string) string {
				fact_key := strings.TrimSuffix(strings.TrimPrefix(expression, "["), "]")
				fact_value, exists := current[fact_key]
				if !exists {
					t.Fatalf("uri_template fact %q is absent from object %#v", fact_key, current)
				}
				return strings.TrimSpace(strings.ReplaceAll(strings.TrimSpace(any_string_create(fact_value)), " ", "%20"))
			})
			if materialized != uri {
				t.Fatalf("uri_template materialized to %q, want %q", materialized, uri)
			}
		}
		for _, child := range current {
			fact_bag_uri_template_validate(t, child)
		}
	case []any:
		for _, child := range current {
			fact_bag_uri_template_validate(t, child)
		}
	}
}

func any_string_create(value any) string {
	encoded, _ := json.Marshal(value)
	return strings.Trim(string(encoded), `"`)
}
