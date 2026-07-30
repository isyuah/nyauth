package settings

import (
	"testing"
	"time"
)

func TestCommunicationsNormalizeAndAnnouncementActivation(t *testing.T) {
	start := time.Date(2026, 7, 29, 8, 0, 0, 0, time.FixedZone("CST", 8*60*60))
	end := start.Add(2 * time.Hour)
	value := DefaultCommunications()
	value.Announcement = Announcement{
		Version: 3, Enabled: true, Severity: AnnouncementSeverityWarning,
		Title: "  Planned change  ", Message: "  Read the details.  ",
		LinkLabel: "Status", LinkURL: "https://status.example.test/incidents/1",
		Dismissible: true, StartsAt: &start, EndsAt: &end,
	}
	normalized, err := NormalizeCommunications(value)
	if err != nil {
		t.Fatalf("NormalizeCommunications: %v", err)
	}
	announcement := normalized.Announcement
	if announcement.Title != "Planned change" || announcement.StartsAt.Location() != time.UTC || announcement.EndsAt.Location() != time.UTC {
		t.Fatalf("announcement was not normalized: %#v", announcement)
	}
	if AnnouncementActiveAt(announcement, announcement.StartsAt.Add(-time.Second)) ||
		!AnnouncementActiveAt(announcement, announcement.StartsAt.Add(time.Second)) ||
		AnnouncementActiveAt(announcement, *announcement.EndsAt) {
		t.Fatal("announcement activation window is incorrect")
	}

	changedVersion := announcement
	changedVersion.Version++
	if !SameAnnouncementContent(announcement, changedVersion) {
		t.Fatal("delivery version must not be part of announcement content equality")
	}
}

func TestCommunicationsRejectUnsafeOrIncompleteAnnouncements(t *testing.T) {
	tests := []Announcement{
		{Enabled: true, Severity: AnnouncementSeverityInfo, Message: "missing title"},
		{Enabled: true, Severity: "notice", Title: "Title", Message: "Body"},
		{Enabled: true, Severity: AnnouncementSeverityInfo, Title: "Title", Message: "Body", LinkLabel: "Open"},
		{Enabled: true, Severity: AnnouncementSeverityInfo, Title: "Title", Message: "Body", LinkLabel: "Open", LinkURL: "http://example.test"},
		{Enabled: true, Severity: AnnouncementSeverityInfo, Title: "Title", Message: "Body", LinkLabel: "Open", LinkURL: "//example.test/path"},
		{Enabled: true, Severity: AnnouncementSeverityInfo, Title: "Title", Message: "Body", LinkLabel: "Open", LinkURL: `/\example.test/path`},
		{Enabled: true, Severity: AnnouncementSeverityInfo, Title: "Title\rInjected", Message: "Body"},
	}
	start := time.Now().UTC()
	end := start.Add(-time.Minute)
	tests = append(tests, Announcement{
		Enabled: true, Severity: AnnouncementSeverityInfo, Title: "Title", Message: "Body",
		StartsAt: &start, EndsAt: &end,
	})
	for index, announcement := range tests {
		value := DefaultCommunications()
		value.Announcement = announcement
		if _, err := NormalizeCommunications(value); err == nil {
			t.Fatalf("case %d: expected validation error for %#v", index, announcement)
		}
	}
}

func TestCommunicationsAllowRootRelativeAnnouncementLinks(t *testing.T) {
	value := DefaultCommunications()
	value.Announcement = Announcement{
		Enabled: true, Severity: AnnouncementSeverityCritical, Title: "Security notice", Message: "Review now.",
		LinkLabel: "Review", LinkURL: "/profile/security?source=announcement",
	}
	if _, err := NormalizeCommunications(value); err != nil {
		t.Fatalf("NormalizeCommunications: %v", err)
	}
}
