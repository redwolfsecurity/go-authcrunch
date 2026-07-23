// Copyright 2026 Paul Greenberg greenpau@outlook.com
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
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
)

func Test_Handle_API_Refresh_Token_Browser_Recovers_Through_Login(t *testing.T) {
	cookie_factory, err := cookie.NewFactory(nil)
	if err != nil {
		t.Fatal(err)
	}
	portal := &Portal{
		config: &PortalConfig{Name: "test_portal"},
		logger: zap.NewNop(),
		cookie: cookie_factory,
	}
	request := httptest.NewRequest(http.MethodGet, "https://localhost/aaa/api/refresh_token", nil)
	request.Header.Set("Accept", "text/html")
	response := httptest.NewRecorder()
	portal_request := requests.NewRequest()
	portal_request.Upstream.BasePath = "/aaa/"

	if err := portal.handleAPI(context.Background(), response, request, portal_request); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusSeeOther {
		t.Fatalf("browser refresh recovery returned status %d, want %d", response.Code, http.StatusSeeOther)
	}
	location := response.Header().Get("Location")
	if location != "/aaa/login?redirect_url=%2Faaa%2Fprofile%2F" {
		t.Fatalf("browser refresh recovery location is %q", location)
	}
	cookie_list := response.Header().Values("Set-Cookie")
	cookie_text := strings.Join(cookie_list, "\n")
	if !strings.Contains(cookie_text, "AUTHP_ACCESS_TOKEN=delete") ||
		!strings.Contains(cookie_text, "AUTHP_REFRESH_TOKEN=delete") ||
		!strings.Contains(cookie_text, "Expires=Thu, 01 Jan 1970 00:00:00 GMT") {
		t.Fatalf("browser refresh recovery did not clear stale token cookies: %v", cookie_list)
	}
}
