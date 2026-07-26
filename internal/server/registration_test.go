package server

import (
	"strings"
	"testing"

	"github.com/nyasharp/nyauth/internal/config"
	"github.com/nyasharp/nyauth/internal/settings"
)

func TestEmailDomainAllowed(t *testing.T) {
	if !emailDomainAllowed("user@anything.example", nil) {
		t.Fatal("empty allowlist must allow every domain")
	}
	allowed := []string{"corp.example.com", "Lab.Example.Org"}
	if !emailDomainAllowed("dev@corp.example.com", allowed) {
		t.Fatal("listed domain was rejected")
	}
	if !emailDomainAllowed("dev@LAB.EXAMPLE.ORG", allowed) {
		t.Fatal("domain comparison must be case-insensitive")
	}
	if emailDomainAllowed("dev@evil.example.com", allowed) {
		t.Fatal("unlisted domain was allowed")
	}
	if emailDomainAllowed("dev@corp.example.com.evil.example", allowed) {
		t.Fatal("suffix spoofing must not pass")
	}
	if emailDomainAllowed("not-an-email", allowed) || emailDomainAllowed("trailing@", allowed) {
		t.Fatal("malformed addresses must not pass a non-empty allowlist")
	}
}

func TestValidEmailDomain(t *testing.T) {
	for _, domain := range []string{"example.com", "a-b.example", "localhost", "x1.y2.z3"} {
		if !validEmailDomain(domain) {
			t.Fatalf("%q must be valid", domain)
		}
	}
	for _, domain := range []string{".example.com", "example.com.", "-example.com", "ex ample.com", "EXAMPLE.com", "ex@mple.com"} {
		if validEmailDomain(domain) {
			t.Fatalf("%q must be invalid", domain)
		}
	}
}

func registrationSettingsTestServer(mailEnabled bool) *Server {
	server := &Server{cfg: &config.Config{}}
	server.cfg.Mail.Enabled = mailEnabled
	if mailEnabled {
		server.accountService = &fakeAccountActionService{}
	}
	return server
}

func TestValidateRegistrationSettingsEnforcesMailDependency(t *testing.T) {
	withoutMail := registrationSettingsTestServer(false)
	if _, err := withoutMail.validateRegistrationSettings(settings.Registration{Mode: settings.RegistrationInviteOnly}); err == nil {
		t.Fatal("invite_only without mail must be rejected")
	}
	if _, err := withoutMail.validateRegistrationSettings(settings.Registration{Mode: settings.RegistrationClosed}); err != nil {
		t.Fatalf("closed mode must not require mail: %v", err)
	}
}

func TestValidateRegistrationSettingsNormalizesInput(t *testing.T) {
	server := registrationSettingsTestServer(true)
	validated, err := server.validateRegistrationSettings(settings.Registration{
		Mode:                     settings.RegistrationOpen,
		RequireEmailVerification: false,
		AllowedEmailDomains:      []string{" Corp.Example.COM ", "corp.example.com", "", "lab.example.org"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !validated.RequireEmailVerification {
		t.Fatal("open mode must force email verification")
	}
	if strings.Join(validated.AllowedEmailDomains, ",") != "corp.example.com,lab.example.org" {
		t.Fatalf("domains = %#v", validated.AllowedEmailDomains)
	}
	if validated.PendingRegistrationTTL != "72h" || validated.InviteDefaultTTL != "168h" || validated.InviteDefaultMaxUses != 1 {
		t.Fatalf("defaults = %#v", validated)
	}
}

func TestValidateRegistrationSettingsRejectsInvalidValues(t *testing.T) {
	server := registrationSettingsTestServer(true)
	cases := []settings.Registration{
		{Mode: "vip"},
		{Mode: settings.RegistrationInviteOnly, AllowedEmailDomains: []string{"bad domain.com"}},
		{Mode: settings.RegistrationInviteOnly, PendingRegistrationTTL: "30m"},
		{Mode: settings.RegistrationInviteOnly, PendingRegistrationTTL: "721h"},
		{Mode: settings.RegistrationInviteOnly, InviteDefaultTTL: "30m"},
		{Mode: settings.RegistrationInviteOnly, InviteDefaultTTL: "9000h"},
		{Mode: settings.RegistrationInviteOnly, InviteDefaultMaxUses: 1001},
		{Mode: settings.RegistrationInviteOnly, InviteDefaultMaxUses: -1},
	}
	for index, request := range cases {
		if _, err := server.validateRegistrationSettings(request); err == nil {
			t.Fatalf("case %d must be rejected: %#v", index, request)
		}
	}
}
