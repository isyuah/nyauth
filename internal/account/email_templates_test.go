package account

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEmailTemplateVariableRulesSerializeEmptyFieldsAsArrays(t *testing.T) {
	encoded, err := json.Marshal(EmailTemplateVariables(MessageEmailVerification))
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(encoded), "null") {
		t.Fatalf("variable rules must not expose null arrays: %s", encoded)
	}
}

func TestStructuredEmailTemplateEscapesContentAndKeepsActionLinkSystemOwned(t *testing.T) {
	settings := DefaultEmailTemplateSettings()
	content := settings.Templates[MessagePasswordReset]
	content.Subject = "[{{site_name}}] 重置密码"
	content.Body = "<strong>{{username}}</strong>，请使用下方的安全链接。"
	settings.Templates[MessagePasswordReset] = content

	message, err := RenderEmailTemplate(MessagePasswordReset, "alice@example.test", EmailPresentation{
		SiteName: "Example <Auth>", Settings: settings,
	}, EmailRenderData{
		Username: "Alice <script>alert(1)</script>", TTL: "30 分钟",
		ActionURL: "https://auth.example.test/reset-password?token=secret",
	})
	if err != nil {
		t.Fatalf("RenderEmailTemplate: %v", err)
	}
	if strings.Contains(message.HTMLBody, "<script>") || strings.Contains(message.HTMLBody, "<strong>") {
		t.Fatalf("admin or user HTML was not escaped: %s", message.HTMLBody)
	}
	for _, expected := range []string{
		"Example &lt;Auth&gt;", "Alice &lt;script&gt;alert(1)&lt;/script&gt;",
		"https://auth.example.test/reset-password?token=secret",
	} {
		if !strings.Contains(message.HTMLBody, expected) {
			t.Fatalf("HTML body does not contain %q: %s", expected, message.HTMLBody)
		}
	}
	if !strings.Contains(message.TextBody, "Alice <script>alert(1)</script>") || message.To != "alice@example.test" {
		t.Fatalf("unexpected text message: %#v", message)
	}
}

func TestEmailTemplateSettingsRejectUnknownVariablesHeadersAndMessageTypes(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*EmailTemplateSettings)
	}{
		{
			name: "unsupported variable",
			mutate: func(value *EmailTemplateSettings) {
				content := value.Templates[MessagePasswordChanged]
				content.Body = "Hello {{username}}"
				value.Templates[MessagePasswordChanged] = content
			},
		},
		{
			name: "personal data in subject",
			mutate: func(value *EmailTemplateSettings) {
				content := value.Templates[MessagePasswordReset]
				content.Subject = "Reset for {{username}}"
				value.Templates[MessagePasswordReset] = content
			},
		},
		{
			name: "required event variable removed",
			mutate: func(value *EmailTemplateSettings) {
				content := value.Templates[MessageRoleChanged]
				content.Body = "Your account changed."
				value.Templates[MessageRoleChanged] = content
			},
		},
		{
			name: "header break",
			mutate: func(value *EmailTemplateSettings) {
				content := value.Templates[MessagePasswordChanged]
				content.Subject = "safe\r\nBcc: attacker@example.test"
				value.Templates[MessagePasswordChanged] = content
			},
		},
		{
			name: "unknown message type",
			mutate: func(value *EmailTemplateSettings) {
				value.Templates["account.arbitrary"] = EmailTemplateContent{Subject: "x", Heading: "x", Body: "x"}
			},
		},
		{
			name: "button on notice",
			mutate: func(value *EmailTemplateSettings) {
				content := value.Templates[MessagePasswordChanged]
				content.ButtonLabel = "Click"
				value.Templates[MessagePasswordChanged] = content
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := DefaultEmailTemplateSettings()
			test.mutate(&value)
			if _, err := NormalizeEmailTemplateSettings(value); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestEmailTemplateSettingsFillMissingKnownTemplatesAndAllowEmptyFooter(t *testing.T) {
	value, err := NormalizeEmailTemplateSettings(EmailTemplateSettings{
		Footer: "", Templates: map[string]EmailTemplateContent{
			MessagePasswordChanged: DefaultEmailTemplateSettings().Templates[MessagePasswordChanged],
		},
	})
	if err != nil {
		t.Fatalf("NormalizeEmailTemplateSettings: %v", err)
	}
	if value.Footer != "" || len(value.Templates) != len(EmailTemplateIDs()) {
		t.Fatalf("normalized settings = %#v", value)
	}
	message, err := RenderEmailTemplate(MessageIdentityBound, "alice@example.test", EmailPresentation{
		SiteName: "Nya", Settings: value,
	}, EmailRenderData{Provider: "github"})
	if err != nil {
		t.Fatalf("RenderEmailTemplate: %v", err)
	}
	if strings.Contains(message.HTMLBody, "href=") || !strings.Contains(message.TextBody, "github") {
		t.Fatalf("unexpected notice rendering: %#v", message)
	}
}
