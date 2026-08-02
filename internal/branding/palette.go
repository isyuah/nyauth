package branding

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Palette is the bounded set of CSS colors derived from one administrator
// selected primary color. It is also used by transactional email rendering so
// browser and email call-to-action text resolve identically.
type Palette struct {
	Primary  string
	RGB      string
	Hover    string
	Active   string
	Soft     string
	Softer   string
	Border   string
	Contrast string
}

type rgb struct {
	r, g, b uint8
}

func NewPalette(primary, textPreference string, dark bool) (Palette, error) {
	color, err := parseHex(primary)
	if err != nil {
		return Palette{}, err
	}
	contrast, err := TextColor(primary, textPreference)
	if err != nil {
		return Palette{}, err
	}
	canvas := rgb{255, 255, 255}
	hoverTarget := rgb{}
	hoverWeight, activeWeight := 0.10, 0.18
	softWeight, softerWeight, borderWeight := 0.88, 0.94, 0.68
	if dark {
		canvas = rgb{23, 23, 32}
		hoverTarget = rgb{255, 255, 255}
		hoverWeight, activeWeight = 0.12, 0.20
		softWeight, softerWeight, borderWeight = 0.76, 0.86, 0.58
	}
	return Palette{
		Primary:  strings.ToUpper(primary),
		RGB:      fmt.Sprintf("%d %d %d", color.r, color.g, color.b),
		Hover:    mix(color, hoverTarget, hoverWeight),
		Active:   mix(color, hoverTarget, activeWeight),
		Soft:     mix(color, canvas, softWeight),
		Softer:   mix(color, canvas, softerWeight),
		Border:   mix(color, canvas, borderWeight),
		Contrast: contrast,
	}, nil
}

func TextColor(primary, preference string) (string, error) {
	color, err := parseHex(primary)
	if err != nil {
		return "", err
	}
	switch strings.ToLower(strings.TrimSpace(preference)) {
	case "", "auto":
		luminance := 0.2126*linear(color.r) + 0.7152*linear(color.g) + 0.0722*linear(color.b)
		whiteContrast := 1.05 / (luminance + 0.05)
		blackContrast := (luminance + 0.05) / 0.05
		if whiteContrast >= blackContrast {
			return "#FFFFFF", nil
		}
		return "#111111", nil
	case "white":
		return "#FFFFFF", nil
	case "black":
		return "#111111", nil
	default:
		return "", errors.New("primary text color must be auto, white, or black")
	}
}

func parseHex(value string) (rgb, error) {
	value = strings.ToUpper(strings.TrimSpace(value))
	if len(value) != 7 || value[0] != '#' {
		return rgb{}, errors.New("primary color must use #RRGGBB format")
	}
	parts := [3]uint8{}
	for index, start := range []int{1, 3, 5} {
		parsed, err := strconv.ParseUint(value[start:start+2], 16, 8)
		if err != nil {
			return rgb{}, errors.New("primary color must use #RRGGBB format")
		}
		parts[index] = uint8(parsed)
	}
	return rgb{parts[0], parts[1], parts[2]}, nil
}

func mix(foreground, background rgb, backgroundWeight float64) string {
	channel := func(front, back uint8) uint8 {
		return uint8(math.Round(float64(front)*(1-backgroundWeight) + float64(back)*backgroundWeight))
	}
	return fmt.Sprintf("#%02X%02X%02X",
		channel(foreground.r, background.r),
		channel(foreground.g, background.g),
		channel(foreground.b, background.b),
	)
}

func linear(value uint8) float64 {
	scaled := float64(value) / 255
	if scaled <= 0.04045 {
		return scaled / 12.92
	}
	return math.Pow((scaled+0.055)/1.055, 2.4)
}
