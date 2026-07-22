// Copyright 2022 Paul Greenberg greenpau@outlook.com
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
	"net/http"
	"net/url"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authchal"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

func Test_Handle_HTTP_Login_Authenticated_Redirect_Default(t *testing.T) {
	p, err := buildGrantAccessPortal(nil, "/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rw := buildCustomResponseWriter()
	r := &http.Request{
		URL:    &url.URL{Scheme: "https", Host: "auth.example.com", Path: "/aaa/login"},
		Method: http.MethodGet,
		Host:   "auth.example.com",
		Header: http.Header{},
	}
	rr := requests.NewRequest()
	rr.Upstream.SessionID = "test-session"
	rr.Upstream.BasePath = "/aaa"
	rr.Upstream.BaseURL = "https://auth.example.com"

	err = p.handleHTTPLogin(context.Background(), rw, r, rr, &user.User{})
	tests.EvalObjectsWithLog(t, "error", nil, err, []string{})
	tests.EvalObjectsWithLog(t, "location", "https://auth.example.com/", rw.Header().Get("Location"), []string{})
}

func TestInjectUserChallenges(t *testing.T) {
	var testcases = []struct {
		name           string
		userChallenges []string
		dataChallenges interface{}
		wantTypes      []string
	}{
		{
			name:           "single-method totp with require mfa collapses generic",
			userChallenges: []string{authchal.PasswordKeyword, authchal.TotpKeyword},
			dataChallenges: []string{authchal.MfaKeyword},
			wantTypes:      []string{authchal.PasswordKeyword, authchal.TotpKeyword},
		},
		{
			name:           "single-method u2f with require mfa collapses generic",
			userChallenges: []string{authchal.PasswordKeyword, authchal.U2fKeyword},
			dataChallenges: []string{authchal.MfaKeyword},
			wantTypes:      []string{authchal.PasswordKeyword, authchal.U2fKeyword},
		},
		{
			name:           "multi-method user with require mfa unchanged",
			userChallenges: []string{authchal.PasswordKeyword, authchal.MfaKeyword},
			dataChallenges: []string{authchal.MfaKeyword},
			wantTypes:      []string{authchal.PasswordKeyword, authchal.MfaKeyword},
		},
		{
			name:           "zero-MFA user with require mfa keeps generic for enrollment",
			userChallenges: []string{authchal.PasswordKeyword},
			dataChallenges: []string{authchal.MfaKeyword},
			wantTypes:      []string{authchal.PasswordKeyword, authchal.MfaKeyword},
		},
		{
			name:           "single-method totp without require mfa unchanged",
			userChallenges: []string{authchal.PasswordKeyword, authchal.TotpKeyword},
			wantTypes:      []string{authchal.PasswordKeyword, authchal.TotpKeyword},
		},
		{
			name:           "nil user challenges with require mfa",
			userChallenges: nil,
			dataChallenges: []string{authchal.MfaKeyword},
			wantTypes:      []string{authchal.MfaKeyword},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Portal{}
			usr := &user.User{}
			data := map[string]interface{}{}
			if tc.dataChallenges != nil {
				data["challenges"] = tc.dataChallenges
			}
			err := p.injectUserChallenges(usr, data, tc.userChallenges)
			tests.EvalObjectsWithLog(t, "error", nil, err, []string{})
			gotTypes := []string{}
			for _, cp := range usr.Checkpoints {
				gotTypes = append(gotTypes, cp.Type)
			}
			tests.EvalObjectsWithLog(t, "checkpoint types", tc.wantTypes, gotTypes, []string{})
		})
	}
}
