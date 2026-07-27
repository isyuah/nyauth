package avatar

import (
	"bytes"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"testing"

	"github.com/gen2brain/webp"
)

func TestProcessorUserUploadRequiresSquareAndProducesVariants(t *testing.T) {
	input := encodePNG(t, solidImage(256, 256))
	processed, err := NewProcessor().ProcessUserUpload(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("ProcessUserUpload() error = %v", err)
	}
	if processed.SourceMediaType != "image/png" || processed.OriginalWidth != 256 || processed.OriginalHeight != 256 {
		t.Fatalf("processed metadata = %#v", processed)
	}
	for _, size := range VariantSizes {
		variant := processed.Variants[size]
		if len(variant) == 0 {
			t.Fatalf("missing %dpx variant", size)
		}
		cfg, err := webp.DecodeConfig(bytes.NewReader(variant))
		if err != nil {
			t.Fatalf("DecodeConfig(%d) error = %v", size, err)
		}
		if cfg.Width != size || cfg.Height != size {
			t.Fatalf("%dpx variant config = %#v", size, cfg)
		}
	}
}

func TestProcessorRejectsNonSquareUserUpload(t *testing.T) {
	input := encodeJPEG(t, solidImage(320, 200))
	_, err := NewProcessor().ProcessUserUpload(bytes.NewReader(input))
	if !errors.Is(err, ErrUserImageNotSquare) {
		t.Fatalf("ProcessUserUpload() error = %v", err)
	}
}

func TestProcessorProviderImageCenterCrops(t *testing.T) {
	input := encodeJPEG(t, solidImage(320, 200))
	processed, err := NewProcessor().ProcessProviderImage(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("ProcessProviderImage() error = %v", err)
	}
	if processed.OriginalWidth != 320 || processed.OriginalHeight != 200 {
		t.Fatalf("processed metadata = %#v", processed)
	}
	cfg, err := webp.DecodeConfig(bytes.NewReader(processed.Variants[128]))
	if err != nil {
		t.Fatalf("DecodeConfig() error = %v", err)
	}
	if cfg.Width != 128 || cfg.Height != 128 {
		t.Fatalf("provider variant config = %#v", cfg)
	}
}

func TestProcessorRejectsUnsupportedAndOversizedInput(t *testing.T) {
	_, err := NewProcessor().ProcessUserUpload(bytes.NewReader([]byte("<svg></svg>")))
	if !errors.Is(err, ErrUnsupportedMedia) {
		t.Fatalf("unsupported input error = %v", err)
	}
	processor := NewProcessor()
	processor.MaxBytes = 4
	_, err = processor.ProcessUserUpload(bytes.NewReader(encodePNG(t, solidImage(8, 8))))
	if !errors.Is(err, ErrImageTooLarge) {
		t.Fatalf("oversized input error = %v", err)
	}
}

func TestProcessorRejectsDimensionsBeforeAcceptingImage(t *testing.T) {
	processor := NewProcessor()
	processor.MaxDimension = 32
	_, err := processor.ProcessUserUpload(bytes.NewReader(encodePNG(t, solidImage(64, 64))))
	if !errors.Is(err, ErrInvalidDimensions) {
		t.Fatalf("oversized dimensions error = %v", err)
	}
}

func TestProcessorRejectsAnimatedWebPContainer(t *testing.T) {
	contents := []byte("RIFF\x10\x00\x00\x00WEBPANIM\x00\x00\x00\x00")
	_, err := NewProcessor().ProcessUserUpload(bytes.NewReader(contents))
	if !errors.Is(err, ErrAnimatedWebP) {
		t.Fatalf("animated WebP error = %v", err)
	}
}

func solidImage(width, height int) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{R: 0x66, G: 0xaa, B: 0xff, A: 0xff})
		}
	}
	return img
}

func encodePNG(t *testing.T, img image.Image) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func encodeJPEG(t *testing.T, img image.Image) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 90}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
