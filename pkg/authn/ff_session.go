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
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/role"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	session_fact_bag "github.com/greenpau/go-authcrunch/pkg/session/fact_bag"
	"github.com/greenpau/go-authcrunch/pkg/user"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
	"go.uber.org/zap"
)

const ff_session_current_path = "/ff/session/current"

// Canonical projection contract:
// @ff/ff_web_server_go/design/session_instance_authcrunch_projection.md

func (p *Portal) ff_session_request_handle(ctx context.Context, writer http.ResponseWriter, request *http.Request, request_record *requests.Request) error {
	p.disableClientCache(writer)
	p.injectSessionID(ctx, writer, request, request_record)
	parsed_user, err := p.authorizeRequest(ctx, writer, request, request_record)
	if err != nil {
		p.logger.Debug(
			"FF session request authorization failed",
			zap.String("session_id", request_record.Upstream.SessionID),
			zap.String("request_id", request_record.ID),
			zap.String("source_address", addrutil.GetSourceAddress(request)),
			zap.Error(err),
		)
		return p.handleJSONErrorWithLog(ctx, writer, request, request_record, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
	}
	if request.Method != http.MethodGet {
		return p.handleJSONError(ctx, writer, http.StatusMethodNotAllowed, http.StatusText(http.StatusMethodNotAllowed))
	}
	if !request_record.Response.Authenticated {
		return p.handleJSONError(ctx, writer, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
	}
	if err := p.authorizedRole(parsed_user, []role.Kind{role.Admin, role.User}, request_record.Response.Authenticated); err != nil {
		return p.handleJSONError(ctx, writer, http.StatusForbidden, http.StatusText(http.StatusForbidden))
	}
	if err := p.ff_session_current_get(writer, request_record, parsed_user, time.Now().UTC()); err != nil {
		p.ff_session_read_error_log(request_record, request, ff_session_current_path, err)
		return p.handleJSONError(ctx, writer, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
	}
	return nil
}

func (p *Portal) ff_session_current_get(writer http.ResponseWriter, request_record *requests.Request, parsed_user *user.User, timestamp_current time.Time) error {
	session_instance, err := session_fact_bag.Session_Instance_Create(request_record, parsed_user, timestamp_current)
	if err != nil {
		return err
	}
	return ff_identity_json_write(writer, session_instance)
}

func (p *Portal) ff_session_read_error_log(request_record *requests.Request, request *http.Request, endpoint_path string, err error) {
	p.logger.Warn(
		"FF session read failed",
		zap.String("session_id", request_record.Upstream.SessionID),
		zap.String("request_id", request_record.ID),
		zap.String("endpoint_path", endpoint_path),
		zap.String("source_address", addrutil.GetSourceAddress(request)),
		zap.Error(err),
	)
}
