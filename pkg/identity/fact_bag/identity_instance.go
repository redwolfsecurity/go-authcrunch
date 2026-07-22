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
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/tagging"
)

const (
	identity_instance_mime_type                    = "identity/instance"
	name_definition_mime_type                      = "name/definition"
	email_address_definition_mime_type             = "email_address/definition"
	authentication_provider_organization_mime_type = "authentication_provider/organization"
	address_definition_mime_type                   = "address/definition"
	password_instance_mime_type                    = "password/instance"
	public_key_instance_mime_type                  = "public_key/instance"
	api_key_instance_mime_type                     = "api_key/instance"
	mfa_token_instance_mime_type                   = "mfa_token/instance"
	mfa_device_definition_mime_type                = "mfa_device/definition"
	tag_definition_mime_type                       = "tag/definition"
	authentication_lockout_mime_type               = "authentication/lockout"
	registration_instance_mime_type                = "registration/instance"
)

// Identity_Instance_Create projects one authcrunch user into a sanitized FF fact bag.
func Identity_Instance_Create(source *identity.User) (*Identity_Instance, error) {
	if source == nil {
		return nil, errors.New("identity source is nil")
	}
	identity_id := strings.TrimSpace(source.ID)
	if identity_id == "" {
		return nil, errors.New("identity source id is empty")
	}
	identity_uri := fact_bag_uri_create(identity_instance_mime_type, identity_id)
	result := &Identity_Instance{
		Mime_Type:                identity_instance_mime_type,
		Identity_ID:              identity_id,
		URI_Template:             "[mime_type]/[identity_id]",
		URI:                      identity_uri,
		Is_Disabled:              source.Disabled,
		Is_Human:                 source.Human,
		User_Name:                strings.TrimSpace(source.Username),
		User_Title:               strings.TrimSpace(source.Title),
		MFA_Failed_Attempt_Count: source.MfaFailedAttempts,
		Created_ISO_8601:         timestamp_iso_8601_create(source.Created),
		Last_Modified_ISO_8601:   timestamp_iso_8601_create(source.LastModified),
		Revision:                 source.Revision,
	}
	if source.Name != nil {
		result.Name_First = strings.TrimSpace(source.Name.First)
		result.Name_Middle = strings.TrimSpace(source.Name.Middle)
		result.Name_Last = strings.TrimSpace(source.Name.Last)
		result.Name_Preferred = strings.TrimSpace(source.Name.Preferred)
	}
	result.Name_List = name_definition_list_create(identity_uri, source.Name, source.Names)
	if source.EmailAddress != nil {
		result.User_Contact_Email = strings.TrimSpace(source.EmailAddress.Address)
	}
	result.User_Contact_Email_List = email_address_definition_list_create(identity_uri, source.EmailAddress, source.EmailAddresses)
	result.Authentication_Provider_Organization_List = authentication_provider_organization_list_create(identity_uri, source.Organization, source.Organizations)
	result.Address_List = address_definition_list_create(identity_uri, source.StreetAddress)
	result.Password_List = password_instance_list_create(identity_uri, source.Passwords)
	result.Public_Key_List = public_key_instance_list_create(identity_uri, source.PublicKeys)
	result.API_Key_List = api_key_instance_list_create(identity_uri, source.APIKeys)
	result.MFA_Token_List = mfa_token_instance_list_create(identity_uri, source.MfaTokens)
	result.Lockout = authentication_lockout_create(identity_uri, source.Lockout)
	if source.Avatar != nil {
		result.Avatar_URI = strings.TrimSpace(source.Avatar.Path)
		result.Avatar_Title = strings.TrimSpace(source.Avatar.Title)
	}
	for _, source_role := range source.Roles {
		if source_role == nil {
			continue
		}
		role_id := strings.TrimSpace(source_role.String())
		if role_id != "" {
			result.Role_List = append(result.Role_List, role_id)
		}
	}
	result.Authentication_Challenge_Rule_List = string_list_nonempty_create(source.AuthChallengeRules)
	result.Registration = registration_instance_create(identity_uri, source.Registration)
	return result, nil
}

func fact_bag_uri_create(part_list ...string) string {
	return strings.Join(part_list, "/")
}

func timestamp_iso_8601_create(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func string_list_nonempty_create(source []string) []string {
	result := make([]string, 0, len(source))
	for _, value := range source {
		value = strings.TrimSpace(value)
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}

func name_definition_list_create(user_uri string, primary *identity.Name, additional []*identity.Name) []Name_Definition {
	source_list := make([]*identity.Name, 0, len(additional)+1)
	if primary != nil {
		source_list = append(source_list, primary)
	}
	source_list = append(source_list, additional...)
	result := make([]Name_Definition, 0, len(source_list))
	seen := make(map[string]bool)
	for _, source := range source_list {
		if source == nil {
			continue
		}
		key := strings.Join([]string{source.First, source.Middle, source.Last, source.Preferred, strconv.FormatBool(source.Nickname), strconv.FormatBool(source.Confirmed), strconv.FormatBool(source.Primary), strconv.FormatBool(source.Legal), strconv.FormatBool(source.Alias)}, "\x00")
		if seen[key] {
			continue
		}
		seen[key] = true
		name_index := len(result)
		result = append(result, Name_Definition{
			Mime_Type: name_definition_mime_type, User_URI: user_uri, Name_Index: name_index,
			URI_Template: "[user_uri]/[mime_type]/[name_index]", URI: fact_bag_uri_create(user_uri, name_definition_mime_type, strconv.Itoa(name_index)),
			Name_First: strings.TrimSpace(source.First), Name_Middle: strings.TrimSpace(source.Middle), Name_Last: strings.TrimSpace(source.Last), Name_Preferred: strings.TrimSpace(source.Preferred),
			Is_Nickname: source.Nickname, Is_Confirmed: source.Confirmed, Is_Primary: source.Primary, Is_Legal: source.Legal, Is_Alias: source.Alias,
		})
	}
	return result
}

func email_address_definition_list_create(user_uri string, primary *identity.EmailAddress, additional []*identity.EmailAddress) []Email_Address_Definition {
	source_list := make([]*identity.EmailAddress, 0, len(additional)+1)
	if primary != nil {
		source_list = append(source_list, primary)
	}
	source_list = append(source_list, additional...)
	result := make([]Email_Address_Definition, 0, len(source_list))
	seen := make(map[string]bool)
	for _, source := range source_list {
		if source == nil {
			continue
		}
		email := strings.TrimSpace(source.Address)
		key := strings.ToLower(email)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, Email_Address_Definition{
			Mime_Type: email_address_definition_mime_type, User_URI: user_uri,
			URI_Template: "[user_uri]/[mime_type]/[user_contact_email]", URI: fact_bag_uri_create(user_uri, email_address_definition_mime_type, email),
			User_Contact_Email: email, Email_Domain: strings.TrimSpace(source.Domain), Is_Confirmed: source.Confirmed,
		})
	}
	return result
}

func authentication_provider_organization_list_create(user_uri string, primary *identity.Organization, additional []*identity.Organization) []Authentication_Provider_Organization {
	source_list := make([]*identity.Organization, 0, len(additional)+1)
	if primary != nil {
		source_list = append(source_list, primary)
	}
	source_list = append(source_list, additional...)
	result := make([]Authentication_Provider_Organization, 0, len(source_list))
	seen := make(map[string]bool)
	for _, source := range source_list {
		if source == nil {
			continue
		}
		organization_id := strings.TrimSpace(source.Name)
		key := strconv.FormatUint(source.ID, 10) + "\x00" + strings.ToLower(organization_id)
		if (source.ID == 0 && organization_id == "") || seen[key] {
			continue
		}
		seen[key] = true
		entry := Authentication_Provider_Organization{
			Mime_Type: authentication_provider_organization_mime_type, User_URI: user_uri,
			Authentication_Provider_Organization_ID: source.ID, Organization_ID: organization_id,
			Organization_Alias_List: string_list_nonempty_create(source.Aliases),
		}
		if source.ID > 0 {
			entry.URI_Template = "[user_uri]/[mime_type]/[authentication_provider_organization_id]"
			entry.URI = fact_bag_uri_create(user_uri, authentication_provider_organization_mime_type, strconv.FormatUint(source.ID, 10))
		} else {
			entry.URI_Template = "[user_uri]/[mime_type]/[organization_id]"
			entry.URI = fact_bag_uri_create(user_uri, authentication_provider_organization_mime_type, organization_id)
		}
		result = append(result, entry)
	}
	return result
}

func address_definition_list_create(user_uri string, source_list []*identity.Location) []Address_Definition {
	result := make([]Address_Definition, 0, len(source_list))
	for _, source := range source_list {
		if source == nil {
			continue
		}
		address_index := len(result)
		result = append(result, Address_Definition{
			Mime_Type: address_definition_mime_type, User_URI: user_uri, Address_Index: address_index,
			URI_Template: "[user_uri]/[mime_type]/[address_index]", URI: fact_bag_uri_create(user_uri, address_definition_mime_type, strconv.Itoa(address_index)),
			Address_Street: strings.TrimSpace(source.Street), Address_City: strings.TrimSpace(source.City), Address_State: strings.TrimSpace(source.State), Address_Postal_Code: strings.TrimSpace(source.ZipCode),
			Is_Confirmed: source.Confirmed, Is_Current: source.Current, Is_Domicile: source.Domicile, Is_Residential: source.Residential, Is_Commercial: source.Commercial,
		})
	}
	return result
}

func password_instance_list_create(user_uri string, source_list []*identity.Password) []Password_Instance {
	result := make([]Password_Instance, 0, len(source_list))
	for source_index, source := range source_list {
		if source == nil {
			continue
		}
		created := timestamp_iso_8601_create(source.CreatedAt)
		entry := Password_Instance{
			Mime_Type: password_instance_mime_type, User_URI: user_uri, Purpose: strings.TrimSpace(source.Purpose), Algorithm: strings.TrimSpace(source.Algorithm), Cost: source.Cost,
			Is_Expired: source.Expired, Expired_ISO_8601: timestamp_iso_8601_create(source.ExpiredAt), Created_ISO_8601: created,
			Is_Disabled: source.Disabled, Disabled_ISO_8601: timestamp_iso_8601_create(source.DisabledAt),
		}
		if created != "" {
			entry.URI_Template = "[user_uri]/[mime_type]/[created_iso_8601]"
			entry.URI = fact_bag_uri_create(user_uri, password_instance_mime_type, created)
		} else {
			index := source_index
			entry.Password_Index = &index
			entry.URI_Template = "[user_uri]/[mime_type]/[password_index]"
			entry.URI = fact_bag_uri_create(user_uri, password_instance_mime_type, strconv.Itoa(index))
		}
		result = append(result, entry)
	}
	return result
}

func public_key_instance_list_create(user_uri string, source_list []*identity.PublicKey) []Public_Key_Instance {
	result := make([]Public_Key_Instance, 0, len(source_list))
	for source_index, source := range source_list {
		if source == nil {
			continue
		}
		entry := Public_Key_Instance{
			Mime_Type: public_key_instance_mime_type, User_URI: user_uri, Public_Key_ID: strings.TrimSpace(source.ID),
			Usage: strings.TrimSpace(source.Usage), Type: strings.TrimSpace(source.Type), Fingerprint: strings.TrimSpace(source.Fingerprint), Fingerprint_MD5: strings.TrimSpace(source.FingerprintMD5),
			Comment: strings.TrimSpace(source.Comment), Description: strings.TrimSpace(source.Description), Is_Expired: source.Expired,
			Expired_ISO_8601: timestamp_iso_8601_create(source.ExpiredAt), Created_ISO_8601: timestamp_iso_8601_create(source.CreatedAt),
			Is_Disabled: source.Disabled, Disabled_ISO_8601: timestamp_iso_8601_create(source.DisabledAt), Label_List: string_list_nonempty_create(source.Labels),
		}
		entry.URI_Template, entry.URI, entry.Public_Key_Index = child_uri_create(user_uri, public_key_instance_mime_type, "public_key_id", entry.Public_Key_ID, "public_key_index", source_index)
		entry.Tag_List = tag_definition_list_create(user_uri, entry.URI, source.Tags)
		result = append(result, entry)
	}
	return result
}

func api_key_instance_list_create(user_uri string, source_list []*identity.APIKey) []API_Key_Instance {
	result := make([]API_Key_Instance, 0, len(source_list))
	for source_index, source := range source_list {
		if source == nil {
			continue
		}
		entry := API_Key_Instance{
			Mime_Type: api_key_instance_mime_type, User_URI: user_uri, API_Key_ID: strings.TrimSpace(source.ID), Prefix: strings.TrimSpace(source.Prefix), Usage: strings.TrimSpace(source.Usage),
			Comment: strings.TrimSpace(source.Comment), Description: strings.TrimSpace(source.Description), Is_Expired: source.Expired,
			Expired_ISO_8601: timestamp_iso_8601_create(source.ExpiredAt), Created_ISO_8601: timestamp_iso_8601_create(source.CreatedAt),
			Is_Disabled: source.Disabled, Disabled_ISO_8601: timestamp_iso_8601_create(source.DisabledAt), Label_List: string_list_nonempty_create(source.Labels),
		}
		entry.URI_Template, entry.URI, entry.API_Key_Index = child_uri_create(user_uri, api_key_instance_mime_type, "api_key_id", entry.API_Key_ID, "api_key_index", source_index)
		entry.Tag_List = tag_definition_list_create(user_uri, entry.URI, source.Tags)
		result = append(result, entry)
	}
	return result
}

func mfa_token_instance_list_create(user_uri string, source_list []*identity.MfaToken) []MFA_Token_Instance {
	result := make([]MFA_Token_Instance, 0, len(source_list))
	for source_index, source := range source_list {
		if source == nil {
			continue
		}
		entry := MFA_Token_Instance{
			Mime_Type: mfa_token_instance_mime_type, User_URI: user_uri, MFA_Token_ID: strings.TrimSpace(source.ID), Type: strings.TrimSpace(source.Type), Algorithm: strings.TrimSpace(source.Algorithm),
			Comment: strings.TrimSpace(source.Comment), Description: strings.TrimSpace(source.Description), Period: source.Period, Digits: source.Digits,
			Is_Expired: source.Expired, Expired_ISO_8601: timestamp_iso_8601_create(source.ExpiredAt), Created_ISO_8601: timestamp_iso_8601_create(source.CreatedAt),
			Is_Disabled: source.Disabled, Disabled_ISO_8601: timestamp_iso_8601_create(source.DisabledAt), Label_List: string_list_nonempty_create(source.Labels),
		}
		entry.URI_Template, entry.URI, entry.MFA_Token_Index = child_uri_create(user_uri, mfa_token_instance_mime_type, "mfa_token_id", entry.MFA_Token_ID, "mfa_token_index", source_index)
		entry.Device = mfa_device_definition_create(entry.URI, source.Device)
		entry.Tag_List = tag_definition_list_create(user_uri, entry.URI, source.Tags)
		result = append(result, entry)
	}
	return result
}

func child_uri_create(user_uri string, mime_type string, id_fact_key string, id string, index_fact_key string, index int) (string, string, *int) {
	if id != "" {
		return "[user_uri]/[mime_type]/[" + id_fact_key + "]", fact_bag_uri_create(user_uri, mime_type, id), nil
	}
	return "[user_uri]/[mime_type]/[" + index_fact_key + "]", fact_bag_uri_create(user_uri, mime_type, strconv.Itoa(index)), &index
}

func mfa_device_definition_create(mfa_token_uri string, source *identity.MfaDevice) *MFA_Device_Definition {
	if source == nil {
		return nil
	}
	name := strings.TrimSpace(source.Name)
	vendor := strings.TrimSpace(source.Vendor)
	device_type := strings.TrimSpace(source.Type)
	if name == "" && vendor == "" && device_type == "" {
		return nil
	}
	return &MFA_Device_Definition{
		Mime_Type: mfa_device_definition_mime_type, MFA_Token_URI: mfa_token_uri,
		URI_Template: "[mfa_token_uri]/[mime_type]", URI: fact_bag_uri_create(mfa_token_uri, mfa_device_definition_mime_type),
		Name: name, Vendor: vendor, Type: device_type,
	}
}

func tag_definition_list_create(user_uri string, parent_uri string, source_list []tagging.Tag) []Tag_Definition {
	result := make([]Tag_Definition, 0, len(source_list))
	for _, source := range source_list {
		key := strings.TrimSpace(source.Key)
		value := strings.TrimSpace(source.Value)
		if key == "" || value == "" {
			continue
		}
		tag_index := len(result)
		result = append(result, Tag_Definition{
			Mime_Type: tag_definition_mime_type, User_URI: user_uri, Parent_URI: parent_uri, Tag_Index: tag_index,
			URI_Template: "[parent_uri]/[mime_type]/[tag_index]", URI: fact_bag_uri_create(parent_uri, tag_definition_mime_type, strconv.Itoa(tag_index)),
			Tag_Key: key, Tag_Value: value,
		})
	}
	return result
}

func authentication_lockout_create(user_uri string, source *identity.LockoutState) *Authentication_Lockout {
	if source == nil {
		return nil
	}
	return &Authentication_Lockout{
		Mime_Type: authentication_lockout_mime_type, User_URI: user_uri,
		URI_Template: "[user_uri]/[mime_type]", URI: fact_bag_uri_create(user_uri, authentication_lockout_mime_type),
		Is_Enabled: source.Enabled, Start_ISO_8601: timestamp_iso_8601_create(source.StartTime), End_ISO_8601: timestamp_iso_8601_create(source.EndTime),
	}
}

func registration_instance_create(user_uri string, source *identity.Registration) *Registration_Instance {
	if source == nil {
		return nil
	}
	registration_id := strings.TrimSpace(source.ID)
	result := &Registration_Instance{
		Mime_Type: registration_instance_mime_type, User_URI: user_uri, Registration_ID: registration_id,
		Created_ISO_8601: timestamp_iso_8601_create(source.CreatedAt), Approved_ISO_8601: timestamp_iso_8601_create(source.ApprovedAt), Is_Approved: source.Approved,
		Declined_ISO_8601: timestamp_iso_8601_create(source.DeclinedAt), Is_Declined: source.Declined,
	}
	if registration_id != "" {
		result.URI_Template = "[user_uri]/[mime_type]/[registration_id]"
		result.URI = fact_bag_uri_create(user_uri, registration_instance_mime_type, registration_id)
	} else {
		result.URI_Template = "[user_uri]/[mime_type]"
		result.URI = fact_bag_uri_create(user_uri, registration_instance_mime_type)
	}
	return result
}
