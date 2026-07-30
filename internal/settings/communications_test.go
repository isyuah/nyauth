package settings

import (
	"strings"
	"testing"
	"time"
)

func TestCommunicationsNormalizeAndSiteBannerActivation(t *testing.T) {
	start := time.Date(2026, 7, 29, 8, 0, 0, 0, time.FixedZone("CST", 8*60*60))
	end := start.Add(2 * time.Hour)
	value := DefaultCommunications()
	value.SiteBanner = SiteBanner{
		Version: 3, Enabled: true, Severity: SiteBannerSeverityWarning,
		Title: "  Planned change  ", Message: "  Read the **details** at [Status](https://status.example.test/incidents/1).  ",
		Dismissible: true, StartsAt: &start, EndsAt: &end,
	}
	normalized, err := NormalizeCommunications(value)
	if err != nil {
		t.Fatalf("NormalizeCommunications: %v", err)
	}
	siteBanner := normalized.SiteBanner
	if siteBanner.Title != "Planned change" || siteBanner.StartsAt.Location() != time.UTC || siteBanner.EndsAt.Location() != time.UTC {
		t.Fatalf("site banner was not normalized: %#v", siteBanner)
	}
	if SiteBannerActiveAt(siteBanner, siteBanner.StartsAt.Add(-time.Second)) ||
		!SiteBannerActiveAt(siteBanner, siteBanner.StartsAt.Add(time.Second)) ||
		SiteBannerActiveAt(siteBanner, *siteBanner.EndsAt) {
		t.Fatal("site banner activation window is incorrect")
	}

	changedVersion := siteBanner
	changedVersion.Version++
	if !SameSiteBannerContent(siteBanner, changedVersion) {
		t.Fatal("delivery version must not be part of site banner content equality")
	}
}

func TestSiteBannerActivationSupportsIndependentOpenBounds(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	start := now.Add(time.Hour)
	end := now.Add(time.Hour)

	for name, value := range map[string]SiteBanner{
		"immediate and indefinite": {Enabled: true, Severity: SiteBannerSeverityInfo, Title: "Now", Message: "Body"},
		"immediate until end":      {Enabled: true, Severity: SiteBannerSeverityInfo, Title: "Now", Message: "Body", EndsAt: &end},
		"start until disabled":     {Enabled: true, Severity: SiteBannerSeverityInfo, Title: "Later", Message: "Body", StartsAt: &start},
	} {
		normalized, err := NormalizeCommunications(Communications{SiteBanner: value})
		if err != nil {
			t.Fatalf("%s: NormalizeCommunications: %v", name, err)
		}
		if !SiteBannerActiveAt(normalized.SiteBanner, now) && name == "immediate and indefinite" {
			t.Fatalf("%s: expected active banner", name)
		}
		if name == "immediate until end" && (!SiteBannerActiveAt(normalized.SiteBanner, now) || SiteBannerActiveAt(normalized.SiteBanner, end)) {
			t.Fatalf("%s: expected [now, end) activation window", name)
		}
		if name == "start until disabled" && (SiteBannerActiveAt(normalized.SiteBanner, now) || !SiteBannerActiveAt(normalized.SiteBanner, start)) {
			t.Fatalf("%s: expected start-open activation window", name)
		}
	}
}

func TestCommunicationsRejectUnsafeOrIncompleteSiteBanners(t *testing.T) {
	tests := []SiteBanner{
		{Enabled: true, Severity: SiteBannerSeverityInfo, Message: "missing title"},
		{Enabled: true, Severity: "notice", Title: "Title", Message: "Body"},
		{Enabled: true, Severity: SiteBannerSeverityInfo, Title: "Title", Message: "[Open](http://example.test)"},
		{Enabled: true, Severity: SiteBannerSeverityInfo, Title: "Title", Message: "[Open](//example.test/path)"},
		{Enabled: true, Severity: SiteBannerSeverityInfo, Title: "Title", Message: `[Open](/\example.test/path)`},
		{Enabled: true, Severity: SiteBannerSeverityInfo, Title: "Title", Message: "<strong>raw HTML</strong>"},
		{Enabled: true, Severity: SiteBannerSeverityInfo, Title: "Title", Message: "![remote image](https://example.test/a.png)"},
		{Enabled: true, Severity: SiteBannerSeverityInfo, Title: "Title\rInjected", Message: "Body"},
	}
	start := time.Now().UTC()
	end := start.Add(-time.Minute)
	tests = append(tests, SiteBanner{
		Enabled: true, Severity: SiteBannerSeverityInfo, Title: "Title", Message: "Body",
		StartsAt: &start, EndsAt: &end,
	})
	for index, siteBanner := range tests {
		value := DefaultCommunications()
		value.SiteBanner = siteBanner
		if _, err := NormalizeCommunications(value); err == nil {
			t.Fatalf("case %d: expected validation error for %#v", index, siteBanner)
		}
	}
}

func TestCommunicationsAllowRootRelativeSiteBannerLinks(t *testing.T) {
	value := DefaultCommunications()
	value.SiteBanner = SiteBanner{
		Enabled: true, Severity: SiteBannerSeverityCritical, Title: "Security notice",
		Message: "[Review now](/profile/security?source=site_banner)",
	}
	if _, err := NormalizeCommunications(value); err != nil {
		t.Fatalf("NormalizeCommunications: %v", err)
	}
}

func TestSiteBannerMarkdownRendersEscapedTextAndSafeLinks(t *testing.T) {
	rendered, err := RenderSiteBannerMarkdown("**Important**: 1 < 2. [Review](/profile/security)")
	if err != nil {
		t.Fatalf("RenderSiteBannerMarkdown: %v", err)
	}
	for _, expected := range []string{"<strong>Important</strong>", "1 &lt; 2", `href="/profile/security"`} {
		if !strings.Contains(rendered, expected) {
			t.Fatalf("rendered Markdown does not contain %q: %s", expected, rendered)
		}
	}
}
