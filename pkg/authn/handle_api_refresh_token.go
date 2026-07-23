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
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
)

func (p *Portal) handleAPIRefreshToken(_ context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, _ *user.User) error {
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		base_path := rr.Upstream.BasePath
		if base_path == "" {
			base_path = "/"
		}
		if !strings.HasSuffix(base_path, "/") {
			base_path += "/"
		}
		w.Header().Add("Set-Cookie", p.cookie.GetDeleteAccessTokenCookie(addrutil.GetSourceHost(r)))
		w.Header().Add("Set-Cookie", p.cookie.GetDeleteRefreshTokenCookie(base_path))
		login_location := base_path + "login?redirect_url=" + url.QueryEscape(base_path+"profile/")
		rr.Response.Code = http.StatusSeeOther
		http.Redirect(w, r, login_location, rr.Response.Code)
		return nil
	}

	w.Header().Set("Content-Type", "application/json")
	rr.Response.Code = http.StatusOK
	resp := make(map[string]interface{})
	resp["timestamp"] = time.Now().UTC().Format(time.RFC3339Nano)
	respBytes, _ := json.Marshal(resp)
	w.WriteHeader(rr.Response.Code)
	w.Write(respBytes)
	return nil
}
