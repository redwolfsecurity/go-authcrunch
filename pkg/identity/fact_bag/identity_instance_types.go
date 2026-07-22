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

// Canonical contract:
// @ff/ff_web_server_go/design/identity_instance_authcrunch_projection.md

// Identity_Instance is the sanitized FF projection of an authcrunch identity.User.
type Identity_Instance struct {
	Mime_Type                                 string                                 `json:"mime_type" xml:"mime_type" yaml:"mime_type"`
	Identity_ID                               string                                 `json:"identity_id" xml:"identity_id" yaml:"identity_id"`
	URI_Template                              string                                 `json:"uri_template" xml:"uri_template" yaml:"uri_template"`
	URI                                       string                                 `json:"uri" xml:"uri" yaml:"uri"`
	Is_Disabled                               bool                                   `json:"is_disabled" xml:"is_disabled" yaml:"is_disabled"`
	Is_Human                                  bool                                   `json:"is_human" xml:"is_human" yaml:"is_human"`
	User_Name                                 string                                 `json:"user_name,omitempty" xml:"user_name,omitempty" yaml:"user_name,omitempty"`
	User_Title                                string                                 `json:"user_title,omitempty" xml:"user_title,omitempty" yaml:"user_title,omitempty"`
	Name_First                                string                                 `json:"name_first,omitempty" xml:"name_first,omitempty" yaml:"name_first,omitempty"`
	Name_Middle                               string                                 `json:"name_middle,omitempty" xml:"name_middle,omitempty" yaml:"name_middle,omitempty"`
	Name_Last                                 string                                 `json:"name_last,omitempty" xml:"name_last,omitempty" yaml:"name_last,omitempty"`
	Name_Preferred                            string                                 `json:"name_preferred,omitempty" xml:"name_preferred,omitempty" yaml:"name_preferred,omitempty"`
	Name_List                                 []Name_Definition                      `json:"name_list,omitempty" xml:"name_list,omitempty" yaml:"name_list,omitempty"`
	User_Contact_Email                        string                                 `json:"user_contact_email,omitempty" xml:"user_contact_email,omitempty" yaml:"user_contact_email,omitempty"`
	User_Contact_Email_List                   []Email_Address_Definition             `json:"user_contact_email_list,omitempty" xml:"user_contact_email_list,omitempty" yaml:"user_contact_email_list,omitempty"`
	Authentication_Provider_Organization_List []Authentication_Provider_Organization `json:"authentication_provider_organization_list,omitempty" xml:"authentication_provider_organization_list,omitempty" yaml:"authentication_provider_organization_list,omitempty"`
	Address_List                              []Address_Definition                   `json:"address_list,omitempty" xml:"address_list,omitempty" yaml:"address_list,omitempty"`
	Password_List                             []Password_Instance                    `json:"password_list,omitempty" xml:"password_list,omitempty" yaml:"password_list,omitempty"`
	Public_Key_List                           []Public_Key_Instance                  `json:"public_key_list,omitempty" xml:"public_key_list,omitempty" yaml:"public_key_list,omitempty"`
	API_Key_List                              []API_Key_Instance                     `json:"api_key_list,omitempty" xml:"api_key_list,omitempty" yaml:"api_key_list,omitempty"`
	MFA_Token_List                            []MFA_Token_Instance                   `json:"mfa_token_list,omitempty" xml:"mfa_token_list,omitempty" yaml:"mfa_token_list,omitempty"`
	Lockout                                   *Authentication_Lockout                `json:"lockout,omitempty" xml:"lockout,omitempty" yaml:"lockout,omitempty"`
	MFA_Failed_Attempt_Count                  int                                    `json:"mfa_failed_attempt_count" xml:"mfa_failed_attempt_count" yaml:"mfa_failed_attempt_count"`
	Avatar_URI                                string                                 `json:"avatar_uri,omitempty" xml:"avatar_uri,omitempty" yaml:"avatar_uri,omitempty"`
	Avatar_Title                              string                                 `json:"avatar_title,omitempty" xml:"avatar_title,omitempty" yaml:"avatar_title,omitempty"`
	Role_List                                 []string                               `json:"role_list,omitempty" xml:"role_list,omitempty" yaml:"role_list,omitempty"`
	Authentication_Challenge_Rule_List        []string                               `json:"authentication_challenge_rule_list,omitempty" xml:"authentication_challenge_rule_list,omitempty" yaml:"authentication_challenge_rule_list,omitempty"`
	Registration                              *Registration_Instance                 `json:"registration,omitempty" xml:"registration,omitempty" yaml:"registration,omitempty"`
	Created_ISO_8601                          string                                 `json:"created_iso_8601,omitempty" xml:"created_iso_8601,omitempty" yaml:"created_iso_8601,omitempty"`
	Last_Modified_ISO_8601                    string                                 `json:"last_modified_iso_8601,omitempty" xml:"last_modified_iso_8601,omitempty" yaml:"last_modified_iso_8601,omitempty"`
	Revision                                  int                                    `json:"revision" xml:"revision" yaml:"revision"`
}

// Name_Definition preserves one authcrunch identity name.
type Name_Definition struct {
	Mime_Type      string `json:"mime_type" xml:"mime_type" yaml:"mime_type"`
	User_URI       string `json:"user_uri" xml:"user_uri" yaml:"user_uri"`
	Name_Index     int    `json:"name_index" xml:"name_index" yaml:"name_index"`
	URI_Template   string `json:"uri_template" xml:"uri_template" yaml:"uri_template"`
	URI            string `json:"uri" xml:"uri" yaml:"uri"`
	Name_First     string `json:"name_first,omitempty" xml:"name_first,omitempty" yaml:"name_first,omitempty"`
	Name_Middle    string `json:"name_middle,omitempty" xml:"name_middle,omitempty" yaml:"name_middle,omitempty"`
	Name_Last      string `json:"name_last,omitempty" xml:"name_last,omitempty" yaml:"name_last,omitempty"`
	Name_Preferred string `json:"name_preferred,omitempty" xml:"name_preferred,omitempty" yaml:"name_preferred,omitempty"`
	Is_Nickname    bool   `json:"is_nickname" xml:"is_nickname" yaml:"is_nickname"`
	Is_Confirmed   bool   `json:"is_confirmed" xml:"is_confirmed" yaml:"is_confirmed"`
	Is_Primary     bool   `json:"is_primary" xml:"is_primary" yaml:"is_primary"`
	Is_Legal       bool   `json:"is_legal" xml:"is_legal" yaml:"is_legal"`
	Is_Alias       bool   `json:"is_alias" xml:"is_alias" yaml:"is_alias"`
}

// Email_Address_Definition preserves one authcrunch email address.
type Email_Address_Definition struct {
	Mime_Type          string `json:"mime_type" xml:"mime_type" yaml:"mime_type"`
	User_URI           string `json:"user_uri" xml:"user_uri" yaml:"user_uri"`
	URI_Template       string `json:"uri_template" xml:"uri_template" yaml:"uri_template"`
	URI                string `json:"uri" xml:"uri" yaml:"uri"`
	User_Contact_Email string `json:"user_contact_email" xml:"user_contact_email" yaml:"user_contact_email"`
	Email_Domain       string `json:"email_domain,omitempty" xml:"email_domain,omitempty" yaml:"email_domain,omitempty"`
	Is_Confirmed       bool   `json:"is_confirmed" xml:"is_confirmed" yaml:"is_confirmed"`
}

// Authentication_Provider_Organization preserves one provider-scoped organization profile.
type Authentication_Provider_Organization struct {
	Mime_Type                               string   `json:"mime_type" xml:"mime_type" yaml:"mime_type"`
	User_URI                                string   `json:"user_uri" xml:"user_uri" yaml:"user_uri"`
	Authentication_Provider_Organization_ID uint64   `json:"authentication_provider_organization_id,omitempty" xml:"authentication_provider_organization_id,omitempty" yaml:"authentication_provider_organization_id,omitempty"`
	URI_Template                            string   `json:"uri_template" xml:"uri_template" yaml:"uri_template"`
	URI                                     string   `json:"uri" xml:"uri" yaml:"uri"`
	Organization_ID                         string   `json:"organization_id,omitempty" xml:"organization_id,omitempty" yaml:"organization_id,omitempty"`
	Organization_Alias_List                 []string `json:"organization_alias_list,omitempty" xml:"organization_alias_list,omitempty" yaml:"organization_alias_list,omitempty"`
}

// Address_Definition preserves one authcrunch street address.
type Address_Definition struct {
	Mime_Type           string `json:"mime_type" xml:"mime_type" yaml:"mime_type"`
	User_URI            string `json:"user_uri" xml:"user_uri" yaml:"user_uri"`
	Address_Index       int    `json:"address_index" xml:"address_index" yaml:"address_index"`
	URI_Template        string `json:"uri_template" xml:"uri_template" yaml:"uri_template"`
	URI                 string `json:"uri" xml:"uri" yaml:"uri"`
	Address_Street      string `json:"address_street,omitempty" xml:"address_street,omitempty" yaml:"address_street,omitempty"`
	Address_City        string `json:"address_city,omitempty" xml:"address_city,omitempty" yaml:"address_city,omitempty"`
	Address_State       string `json:"address_state,omitempty" xml:"address_state,omitempty" yaml:"address_state,omitempty"`
	Address_Postal_Code string `json:"address_postal_code,omitempty" xml:"address_postal_code,omitempty" yaml:"address_postal_code,omitempty"`
	Is_Confirmed        bool   `json:"is_confirmed" xml:"is_confirmed" yaml:"is_confirmed"`
	Is_Current          bool   `json:"is_current" xml:"is_current" yaml:"is_current"`
	Is_Domicile         bool   `json:"is_domicile" xml:"is_domicile" yaml:"is_domicile"`
	Is_Residential      bool   `json:"is_residential" xml:"is_residential" yaml:"is_residential"`
	Is_Commercial       bool   `json:"is_commercial" xml:"is_commercial" yaml:"is_commercial"`
}

// Password_Instance discloses password lifecycle metadata without the password hash.
type Password_Instance struct {
	Mime_Type         string `json:"mime_type" xml:"mime_type" yaml:"mime_type"`
	User_URI          string `json:"user_uri" xml:"user_uri" yaml:"user_uri"`
	Password_Index    *int   `json:"password_index,omitempty" xml:"password_index,omitempty" yaml:"password_index,omitempty"`
	URI_Template      string `json:"uri_template" xml:"uri_template" yaml:"uri_template"`
	URI               string `json:"uri" xml:"uri" yaml:"uri"`
	Purpose           string `json:"purpose,omitempty" xml:"purpose,omitempty" yaml:"purpose,omitempty"`
	Algorithm         string `json:"algorithm,omitempty" xml:"algorithm,omitempty" yaml:"algorithm,omitempty"`
	Cost              int    `json:"cost,omitempty" xml:"cost,omitempty" yaml:"cost,omitempty"`
	Is_Expired        bool   `json:"is_expired" xml:"is_expired" yaml:"is_expired"`
	Expired_ISO_8601  string `json:"expired_iso_8601,omitempty" xml:"expired_iso_8601,omitempty" yaml:"expired_iso_8601,omitempty"`
	Created_ISO_8601  string `json:"created_iso_8601,omitempty" xml:"created_iso_8601,omitempty" yaml:"created_iso_8601,omitempty"`
	Is_Disabled       bool   `json:"is_disabled" xml:"is_disabled" yaml:"is_disabled"`
	Disabled_ISO_8601 string `json:"disabled_iso_8601,omitempty" xml:"disabled_iso_8601,omitempty" yaml:"disabled_iso_8601,omitempty"`
}

// Public_Key_Instance discloses public-key metadata without key payload material.
type Public_Key_Instance struct {
	Mime_Type         string           `json:"mime_type" xml:"mime_type" yaml:"mime_type"`
	User_URI          string           `json:"user_uri" xml:"user_uri" yaml:"user_uri"`
	Public_Key_ID     string           `json:"public_key_id,omitempty" xml:"public_key_id,omitempty" yaml:"public_key_id,omitempty"`
	Public_Key_Index  *int             `json:"public_key_index,omitempty" xml:"public_key_index,omitempty" yaml:"public_key_index,omitempty"`
	URI_Template      string           `json:"uri_template" xml:"uri_template" yaml:"uri_template"`
	URI               string           `json:"uri" xml:"uri" yaml:"uri"`
	Usage             string           `json:"usage,omitempty" xml:"usage,omitempty" yaml:"usage,omitempty"`
	Type              string           `json:"type,omitempty" xml:"type,omitempty" yaml:"type,omitempty"`
	Fingerprint       string           `json:"fingerprint,omitempty" xml:"fingerprint,omitempty" yaml:"fingerprint,omitempty"`
	Fingerprint_MD5   string           `json:"fingerprint_md5,omitempty" xml:"fingerprint_md5,omitempty" yaml:"fingerprint_md5,omitempty"`
	Comment           string           `json:"comment,omitempty" xml:"comment,omitempty" yaml:"comment,omitempty"`
	Description       string           `json:"description,omitempty" xml:"description,omitempty" yaml:"description,omitempty"`
	Is_Expired        bool             `json:"is_expired" xml:"is_expired" yaml:"is_expired"`
	Expired_ISO_8601  string           `json:"expired_iso_8601,omitempty" xml:"expired_iso_8601,omitempty" yaml:"expired_iso_8601,omitempty"`
	Created_ISO_8601  string           `json:"created_iso_8601,omitempty" xml:"created_iso_8601,omitempty" yaml:"created_iso_8601,omitempty"`
	Is_Disabled       bool             `json:"is_disabled" xml:"is_disabled" yaml:"is_disabled"`
	Disabled_ISO_8601 string           `json:"disabled_iso_8601,omitempty" xml:"disabled_iso_8601,omitempty" yaml:"disabled_iso_8601,omitempty"`
	Tag_List          []Tag_Definition `json:"tag_list,omitempty" xml:"tag_list,omitempty" yaml:"tag_list,omitempty"`
	Label_List        []string         `json:"label_list,omitempty" xml:"label_list,omitempty" yaml:"label_list,omitempty"`
}

// API_Key_Instance discloses API-key metadata without the API-key payload.
type API_Key_Instance struct {
	Mime_Type         string           `json:"mime_type" xml:"mime_type" yaml:"mime_type"`
	User_URI          string           `json:"user_uri" xml:"user_uri" yaml:"user_uri"`
	API_Key_ID        string           `json:"api_key_id,omitempty" xml:"api_key_id,omitempty" yaml:"api_key_id,omitempty"`
	API_Key_Index     *int             `json:"api_key_index,omitempty" xml:"api_key_index,omitempty" yaml:"api_key_index,omitempty"`
	URI_Template      string           `json:"uri_template" xml:"uri_template" yaml:"uri_template"`
	URI               string           `json:"uri" xml:"uri" yaml:"uri"`
	Prefix            string           `json:"prefix,omitempty" xml:"prefix,omitempty" yaml:"prefix,omitempty"`
	Usage             string           `json:"usage,omitempty" xml:"usage,omitempty" yaml:"usage,omitempty"`
	Comment           string           `json:"comment,omitempty" xml:"comment,omitempty" yaml:"comment,omitempty"`
	Description       string           `json:"description,omitempty" xml:"description,omitempty" yaml:"description,omitempty"`
	Is_Expired        bool             `json:"is_expired" xml:"is_expired" yaml:"is_expired"`
	Expired_ISO_8601  string           `json:"expired_iso_8601,omitempty" xml:"expired_iso_8601,omitempty" yaml:"expired_iso_8601,omitempty"`
	Created_ISO_8601  string           `json:"created_iso_8601,omitempty" xml:"created_iso_8601,omitempty" yaml:"created_iso_8601,omitempty"`
	Is_Disabled       bool             `json:"is_disabled" xml:"is_disabled" yaml:"is_disabled"`
	Disabled_ISO_8601 string           `json:"disabled_iso_8601,omitempty" xml:"disabled_iso_8601,omitempty" yaml:"disabled_iso_8601,omitempty"`
	Tag_List          []Tag_Definition `json:"tag_list,omitempty" xml:"tag_list,omitempty" yaml:"tag_list,omitempty"`
	Label_List        []string         `json:"label_list,omitempty" xml:"label_list,omitempty" yaml:"label_list,omitempty"`
}

// MFA_Token_Instance discloses authenticator metadata without secrets or verification state.
type MFA_Token_Instance struct {
	Mime_Type         string                 `json:"mime_type" xml:"mime_type" yaml:"mime_type"`
	User_URI          string                 `json:"user_uri" xml:"user_uri" yaml:"user_uri"`
	MFA_Token_ID      string                 `json:"mfa_token_id,omitempty" xml:"mfa_token_id,omitempty" yaml:"mfa_token_id,omitempty"`
	MFA_Token_Index   *int                   `json:"mfa_token_index,omitempty" xml:"mfa_token_index,omitempty" yaml:"mfa_token_index,omitempty"`
	URI_Template      string                 `json:"uri_template" xml:"uri_template" yaml:"uri_template"`
	URI               string                 `json:"uri" xml:"uri" yaml:"uri"`
	Type              string                 `json:"type,omitempty" xml:"type,omitempty" yaml:"type,omitempty"`
	Algorithm         string                 `json:"algorithm,omitempty" xml:"algorithm,omitempty" yaml:"algorithm,omitempty"`
	Comment           string                 `json:"comment,omitempty" xml:"comment,omitempty" yaml:"comment,omitempty"`
	Description       string                 `json:"description,omitempty" xml:"description,omitempty" yaml:"description,omitempty"`
	Period            int                    `json:"period,omitempty" xml:"period,omitempty" yaml:"period,omitempty"`
	Digits            int                    `json:"digits,omitempty" xml:"digits,omitempty" yaml:"digits,omitempty"`
	Is_Expired        bool                   `json:"is_expired" xml:"is_expired" yaml:"is_expired"`
	Expired_ISO_8601  string                 `json:"expired_iso_8601,omitempty" xml:"expired_iso_8601,omitempty" yaml:"expired_iso_8601,omitempty"`
	Created_ISO_8601  string                 `json:"created_iso_8601,omitempty" xml:"created_iso_8601,omitempty" yaml:"created_iso_8601,omitempty"`
	Is_Disabled       bool                   `json:"is_disabled" xml:"is_disabled" yaml:"is_disabled"`
	Disabled_ISO_8601 string                 `json:"disabled_iso_8601,omitempty" xml:"disabled_iso_8601,omitempty" yaml:"disabled_iso_8601,omitempty"`
	Device            *MFA_Device_Definition `json:"device,omitempty" xml:"device,omitempty" yaml:"device,omitempty"`
	Tag_List          []Tag_Definition       `json:"tag_list,omitempty" xml:"tag_list,omitempty" yaml:"tag_list,omitempty"`
	Label_List        []string               `json:"label_list,omitempty" xml:"label_list,omitempty" yaml:"label_list,omitempty"`
}

// MFA_Device_Definition preserves descriptive MFA device metadata.
type MFA_Device_Definition struct {
	Mime_Type     string `json:"mime_type" xml:"mime_type" yaml:"mime_type"`
	MFA_Token_URI string `json:"mfa_token_uri" xml:"mfa_token_uri" yaml:"mfa_token_uri"`
	URI_Template  string `json:"uri_template" xml:"uri_template" yaml:"uri_template"`
	URI           string `json:"uri" xml:"uri" yaml:"uri"`
	Name          string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Vendor        string `json:"vendor,omitempty" xml:"vendor,omitempty" yaml:"vendor,omitempty"`
	Type          string `json:"type,omitempty" xml:"type,omitempty" yaml:"type,omitempty"`
}

// Tag_Definition preserves one non-empty authcrunch credential tag.
type Tag_Definition struct {
	Mime_Type    string `json:"mime_type" xml:"mime_type" yaml:"mime_type"`
	User_URI     string `json:"user_uri" xml:"user_uri" yaml:"user_uri"`
	Parent_URI   string `json:"parent_uri" xml:"parent_uri" yaml:"parent_uri"`
	Tag_Index    int    `json:"tag_index" xml:"tag_index" yaml:"tag_index"`
	URI_Template string `json:"uri_template" xml:"uri_template" yaml:"uri_template"`
	URI          string `json:"uri" xml:"uri" yaml:"uri"`
	Tag_Key      string `json:"tag_key" xml:"tag_key" yaml:"tag_key"`
	Tag_Value    string `json:"tag_value" xml:"tag_value" yaml:"tag_value"`
}

// Authentication_Lockout preserves the local identity lockout state.
type Authentication_Lockout struct {
	Mime_Type      string `json:"mime_type" xml:"mime_type" yaml:"mime_type"`
	User_URI       string `json:"user_uri" xml:"user_uri" yaml:"user_uri"`
	URI_Template   string `json:"uri_template" xml:"uri_template" yaml:"uri_template"`
	URI            string `json:"uri" xml:"uri" yaml:"uri"`
	Is_Enabled     bool   `json:"is_enabled" xml:"is_enabled" yaml:"is_enabled"`
	Start_ISO_8601 string `json:"start_iso_8601,omitempty" xml:"start_iso_8601,omitempty" yaml:"start_iso_8601,omitempty"`
	End_ISO_8601   string `json:"end_iso_8601,omitempty" xml:"end_iso_8601,omitempty" yaml:"end_iso_8601,omitempty"`
}

// Registration_Instance preserves the local identity registration lifecycle.
type Registration_Instance struct {
	Mime_Type         string `json:"mime_type" xml:"mime_type" yaml:"mime_type"`
	User_URI          string `json:"user_uri" xml:"user_uri" yaml:"user_uri"`
	Registration_ID   string `json:"registration_id,omitempty" xml:"registration_id,omitempty" yaml:"registration_id,omitempty"`
	URI_Template      string `json:"uri_template" xml:"uri_template" yaml:"uri_template"`
	URI               string `json:"uri" xml:"uri" yaml:"uri"`
	Created_ISO_8601  string `json:"created_iso_8601,omitempty" xml:"created_iso_8601,omitempty" yaml:"created_iso_8601,omitempty"`
	Approved_ISO_8601 string `json:"approved_iso_8601,omitempty" xml:"approved_iso_8601,omitempty" yaml:"approved_iso_8601,omitempty"`
	Is_Approved       bool   `json:"is_approved" xml:"is_approved" yaml:"is_approved"`
	Declined_ISO_8601 string `json:"declined_iso_8601,omitempty" xml:"declined_iso_8601,omitempty" yaml:"declined_iso_8601,omitempty"`
	Is_Declined       bool   `json:"is_declined" xml:"is_declined" yaml:"is_declined"`
}
