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
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn/ui"
)

func TestRebaseAppAssetContent(t *testing.T) {
	testcases := []struct {
		name        string
		content     string
		contentType string
		appName     string
		basePath    string
		want        string
	}{
		{
			name:        "preserve the default authentication portal mount",
			content:     `<base href="/auth/profile/">`,
			contentType: "text/html",
			appName:     "profile",
			basePath:    "/auth/",
			want:        `<base href="/auth/profile/">`,
		},
		{
			name:        "rebase an alternate authentication portal mount",
			content:     `<base href="/auth/profile/">`,
			contentType: "text/html",
			appName:     "profile",
			basePath:    "/aaa/",
			want:        `<base href="/aaa/profile/">`,
		},
		{
			name:        "rebase plain and escaped JavaScript paths",
			content:     "const base = `/auth/profile/`; href.replace(/\\/auth\\/profile\\//gi, `/`)",
			contentType: "application/javascript",
			appName:     "profile",
			basePath:    "/aaa/",
			want:        "const base = `/aaa/profile/`; href.replace(/\\/aaa\\/profile\\//gi, `/`)",
		},
		{
			name:        "leave binary assets unchanged",
			content:     "/auth/profile/",
			contentType: "image/png",
			appName:     "profile",
			basePath:    "/aaa/",
			want:        "/auth/profile/",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got := rebaseAppAssetContent(tc.content, tc.contentType, tc.appName, tc.basePath)
			if got != tc.want {
				t.Fatalf("unexpected rebased app asset content: got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRebaseAppAssetContentProfileBundle(t *testing.T) {
	asset, err := ui.AppAssets.GetAsset("profile/assets/index-YxE65L9G.js")
	if err != nil {
		t.Fatal(err)
	}

	content := rebaseAppAssetContent(asset.Content, asset.ContentType, "profile", "/aaa/")
	for _, unexpected := range []string{"/auth/profile/", `\/auth\/profile\/`} {
		if strings.Contains(content, unexpected) {
			t.Fatalf("rebased profile bundle retains default path %q", unexpected)
		}
	}
	for _, expected := range []string{"/aaa/profile/", `\/aaa\/profile\/`} {
		if !strings.Contains(content, expected) {
			t.Fatalf("rebased profile bundle is missing active path %q", expected)
		}
	}
}
