package branding

import "testing"

func TestNewPaletteMatchesWebColorContract(t *testing.T) {
	light, err := NewPalette("#704DE8", "auto", false)
	if err != nil {
		t.Fatal(err)
	}
	if light.RGB != "112 77 232" || light.Hover != "#6545D1" || light.Active != "#5C3FBE" ||
		light.Soft != "#EEEAFC" || light.Softer != "#F6F4FE" || light.Border != "#D1C6F8" || light.Contrast != "#FFFFFF" {
		t.Fatalf("light palette = %#v", light)
	}
	dark, err := NewPalette("#704DE8", "white", true)
	if err != nil {
		t.Fatal(err)
	}
	if dark.Hover != "#8162EB" || dark.Active != "#8D71ED" || dark.Soft != "#2C2450" ||
		dark.Softer != "#231F3C" || dark.Border != "#3C2E74" || dark.Contrast != "#FFFFFF" {
		t.Fatalf("dark palette = %#v", dark)
	}
}

func TestTextColorAllowsBoundedManualOverride(t *testing.T) {
	if got, err := TextColor("#F6D365", "white"); err != nil || got != "#FFFFFF" {
		t.Fatalf("white override = %q, %v", got, err)
	}
	if got, err := TextColor("#111111", "black"); err != nil || got != "#111111" {
		t.Fatalf("black override = %q, %v", got, err)
	}
	for _, invalid := range [][2]string{{"red", "auto"}, {"#704DE8", "purple"}} {
		if _, err := TextColor(invalid[0], invalid[1]); err == nil {
			t.Fatalf("TextColor(%q, %q) accepted", invalid[0], invalid[1])
		}
	}
}
