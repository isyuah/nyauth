package notification

import (
	"strings"
	"testing"
	"time"
)

func TestNotificationTypeCatalogFailsClosed(t *testing.T) {
	valid := []NotificationType{TypePasswordChanged, TypeEmailChanged, TypeMFAChanged, TypePasskeyChanged, TypeIdentityChanged, TypeAuthorizationRevoked, TypePublisherVerified, TypePublisherRevoked, TypeDeviceAuthorized}
	for _, item := range valid {
		if !item.Valid() {
			t.Fatalf("catalog type %q is invalid", item)
		}
	}
	for _, item := range []NotificationType{"", "security.unknown", "oauth.publisher_verified.extra"} {
		if item.Valid() {
			t.Fatalf("unknown type %q is valid", item)
		}
	}
}

func TestNormalizeMessageCenterOptions(t *testing.T) {
	from := time.Date(2026, 8, 4, 8, 0, 0, 0, time.FixedZone("test", 8*60*60))
	to := from.Add(time.Hour)
	value, err := normalizeMessageCenterOptions(MessageCenterOptions{PageSize: 500, Query: "  security  ", From: &from, To: &to})
	if err != nil {
		t.Fatalf("normalize message options: %v", err)
	}
	if value.Kind != MessageKindAll || value.Read != MessageReadAll || value.Page != 1 || value.PageSize != 100 || value.Query != "security" || value.From.Location() != time.UTC || value.To.Location() != time.UTC {
		t.Fatalf("unexpected normalized options: %#v", value)
	}
	for name, options := range map[string]MessageCenterOptions{
		"kind":     {Kind: "unknown"},
		"read":     {Read: "unknown"},
		"severity": {Severity: "unknown"},
		"range":    {From: &to, To: &from},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := normalizeMessageCenterOptions(options); err == nil {
				t.Fatal("invalid message options accepted")
			}
		})
	}
}

func TestNormalizeAnnouncementRejectsUnsafeContent(t *testing.T) {
	base := AnnouncementInput{Severity: SeverityInfo, Audience: AudienceAuthenticated, Title: "Release", BodyMarkdown: "Safe **body**"}
	if _, err := normalizeInput(base, true); err != nil {
		t.Fatalf("safe announcement: %v", err)
	}
	for name, mutate := range map[string]func(*AnnouncementInput){
		"raw HTML":        func(value *AnnouncementInput) { value.BodyMarkdown = "<script>alert(1)</script>" },
		"image":           func(value *AnnouncementInput) { value.BodyMarkdown = "![tracking](https://example.com/a.png)" },
		"javascript link": func(value *AnnouncementInput) { value.BodyMarkdown = "[open](javascript:alert(1))" },
		"control":         func(value *AnnouncementInput) { value.Title = "title\u202e" },
	} {
		t.Run(name, func(t *testing.T) {
			value := base
			mutate(&value)
			if _, err := normalizeInput(value, true); err == nil {
				t.Fatal("unsafe content accepted")
			}
		})
	}
}

func TestNormalizeAnnouncementAllowsRootRelativeAndHTTPSLinks(t *testing.T) {
	for _, link := range []string{"/profile/security", "https://status.example.test/notice"} {
		value := AnnouncementInput{Title: "Notice", BodyMarkdown: "Body", LinkURL: link}
		if _, err := normalizeInput(value, true); err != nil {
			t.Fatalf("link %q: %v", link, err)
		}
	}
	value := AnnouncementInput{Title: "Notice", BodyMarkdown: "Body", LinkURL: "//evil.example/path"}
	if _, err := normalizeInput(value, true); err == nil || !strings.Contains(err.Error(), "link") {
		t.Fatalf("protocol-relative link error = %v", err)
	}
}
