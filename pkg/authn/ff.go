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
	"net/http"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func (p *Portal) ff_request_handle(ctx context.Context, writer http.ResponseWriter, request *http.Request, request_record *requests.Request) error {
	switch {
	case strings.HasSuffix(request.URL.Path, ff_identity_current_path),
		strings.HasSuffix(request.URL.Path, ff_identity_list_path):
		return p.ff_identity_request_handle(ctx, writer, request, request_record)
	case strings.HasSuffix(request.URL.Path, ff_session_current_path):
		return p.ff_session_request_handle(ctx, writer, request, request_record)
	default:
		return p.handleJSONError(ctx, writer, http.StatusNotFound, http.StatusText(http.StatusNotFound))
	}
}
