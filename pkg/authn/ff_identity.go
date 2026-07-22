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
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/role"
	identity_fact_bag "github.com/greenpau/go-authcrunch/pkg/identity/fact_bag"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
	"go.uber.org/zap"
)

const (
	ff_identity_current_path = "/ff/identity/current"
	ff_identity_list_path    = "/ff/identity/list"
)

// Canonical projection contract:
// @ff/ff_web_server_go/design/identity_instance_authcrunch_projection.md

type ff_identity_store interface {
	Identity_Fact_Bag_Get(*requests.Request) (*identity_fact_bag.Identity_Instance, error)
	Identity_Fact_Bag_List() ([]*identity_fact_bag.Identity_Instance, error)
}

func (p *Portal) ff_identity_request_handle(ctx context.Context, writer http.ResponseWriter, request *http.Request, request_record *requests.Request) error {
	p.disableClientCache(writer)
	p.injectSessionID(ctx, writer, request, request_record)
	parsed_user, err := p.authorizeRequest(ctx, writer, request, request_record)
	if err != nil {
		p.logger.Debug(
			"FF identity request authorization failed",
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
	switch {
	case strings.HasSuffix(request.URL.Path, ff_identity_current_path):
		if !p.config.API.ProfileEnabled {
			return p.handleJSONError(ctx, writer, http.StatusNotFound, http.StatusText(http.StatusNotFound))
		}
		if err := p.authorizedRole(parsed_user, []role.Kind{role.Admin, role.User}, request_record.Response.Authenticated); err != nil {
			return p.handleJSONError(ctx, writer, http.StatusForbidden, http.StatusText(http.StatusForbidden))
		}
		if err := p.ff_identity_current_get(writer, request_record, parsed_user); err != nil {
			p.ff_identity_read_error_log(request_record, request, ff_identity_current_path, err)
			return p.handleJSONError(ctx, writer, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
		}
		return nil
	case strings.HasSuffix(request.URL.Path, ff_identity_list_path):
		if !p.config.API.AdminEnabled {
			return p.handleJSONError(ctx, writer, http.StatusNotFound, http.StatusText(http.StatusNotFound))
		}
		if err := p.authorizedRole(parsed_user, []role.Kind{role.Admin}, request_record.Response.Authenticated); err != nil {
			return p.handleJSONError(ctx, writer, http.StatusForbidden, http.StatusText(http.StatusForbidden))
		}
		if err := p.ff_identity_list_get(writer, request_record, parsed_user); err != nil {
			p.ff_identity_read_error_log(request_record, request, ff_identity_list_path, err)
			return p.handleJSONError(ctx, writer, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
		}
		return nil
	default:
		return p.handleJSONError(ctx, writer, http.StatusNotFound, http.StatusText(http.StatusNotFound))
	}
}

func (p *Portal) ff_identity_read_error_log(request_record *requests.Request, request *http.Request, endpoint_path string, err error) {
	p.logger.Warn(
		"FF identity read failed",
		zap.String("session_id", request_record.Upstream.SessionID),
		zap.String("request_id", request_record.ID),
		zap.String("endpoint_path", endpoint_path),
		zap.String("source_address", addrutil.GetSourceAddress(request)),
		zap.Error(err),
	)
}

func (p *Portal) ff_identity_current_get(writer http.ResponseWriter, request_record *requests.Request, parsed_user *user.User) error {
	store, err := p.ff_identity_store_get(parsed_user)
	if err != nil {
		return err
	}
	request_record.User.Username = parsed_user.Claims.Subject
	request_record.User.Email = parsed_user.Claims.Email
	identity_instance, err := store.Identity_Fact_Bag_Get(request_record)
	if err != nil {
		return err
	}
	return ff_identity_json_write(writer, identity_instance)
}

func (p *Portal) ff_identity_list_get(writer http.ResponseWriter, request_record *requests.Request, parsed_user *user.User) error {
	store, err := p.ff_identity_store_get(parsed_user)
	if err != nil {
		return err
	}
	identity_list, err := store.Identity_Fact_Bag_List()
	if err != nil {
		return err
	}
	return ff_identity_json_write(writer, identity_list)
}

func (p *Portal) ff_identity_store_get(parsed_user *user.User) (ff_identity_store, error) {
	if parsed_user == nil || parsed_user.Claims == nil {
		return nil, errors.New("authenticated identity claims are unavailable")
	}
	realm := strings.TrimSpace(parsed_user.GetClaimValueByField("realm"))
	if realm == "" {
		realm = strings.TrimSpace(parsed_user.Authenticator.Realm)
	}
	if realm == "" {
		return nil, errors.New("authenticated identity realm is unavailable")
	}
	identity_store := p.getIdentityStoreByRealm(realm)
	if identity_store == nil {
		return nil, errors.New("authenticated identity store is unavailable")
	}
	store, valid := identity_store.(ff_identity_store)
	if !valid {
		return nil, errors.New("authenticated identity store does not support FF identity projection")
	}
	return store, nil
}

func ff_identity_json_write(writer http.ResponseWriter, value any) error {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
