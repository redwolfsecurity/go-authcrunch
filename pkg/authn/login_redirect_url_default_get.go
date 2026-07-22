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
	"net/url"
	"path"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func (p *Portal) login_redirect_url_default_get(rr *requests.Request) string {
	portal_redirect_url := rr.Upstream.BaseURL + path.Join(rr.Upstream.BasePath, "/portal")
	if p.config == nil || p.config.UI == nil {
		return portal_redirect_url
	}

	auto_redirect_url := strings.TrimSpace(p.config.UI.AutoRedirectURL)
	if auto_redirect_url == "" {
		return portal_redirect_url
	}

	redirect_url, err := url.Parse(auto_redirect_url)
	if err != nil {
		return portal_redirect_url
	}
	if redirect_url.IsAbs() {
		if redirect_url.Host == "" || (redirect_url.Scheme != "http" && redirect_url.Scheme != "https") {
			return portal_redirect_url
		}
		return redirect_url.String()
	}
	if redirect_url.Host != "" || !strings.HasPrefix(redirect_url.Path, "/") {
		return portal_redirect_url
	}
	return rr.Upstream.BaseURL + redirect_url.String()
}
