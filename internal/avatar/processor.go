package avatar

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"math"

	"github.com/gen2brain/webp"
	"golang.org/x/image/draw"
)

type Processor struct {
	MaxBytes     int64
	MaxDimension int
	MaxPixels    int
	Quality      int
}

func NewProcessor() Processor {
	return Processor{
		MaxBytes:     MaxUploadBytes,
		MaxDimension: MaxDimension,
		MaxPixels:    MaxPixels,
		Quality:      WebPQuality,
	}
}

func (p Processor) ProcessUserUpload(r io.Reader) (ProcessedImage, error) {
	return p.process(r, true)
}

func (p Processor) ProcessProviderImage(r io.Reader) (ProcessedImage, error) {
	return p.process(r, false)
}

func (p Processor) process(r io.Reader, requireSquare bool) (ProcessedImage, error) {
	if p.MaxBytes <= 0 {
		p.MaxBytes = MaxUploadBytes
	}
	if p.MaxDimension <= 0 {
		p.MaxDimension = MaxDimension
	}
	if p.MaxPixels <= 0 {
		p.MaxPixels = MaxPixels
	}
	if p.Quality <= 0 {
		p.Quality = WebPQuality
	}
	limited := io.LimitReader(r, p.MaxBytes+1)
	contents, err := io.ReadAll(limited)
	if err != nil {
		return ProcessedImage{}, fmt.Errorf("reading avatar image: %w", err)
	}
	if int64(len(contents)) > p.MaxBytes {
		return ProcessedImage{}, ErrImageTooLarge
	}
	mediaType, err := sniffAvatarMedia(contents)
	if err != nil {
		return ProcessedImage{}, err
	}
	cfg, err := decodeAvatarConfig(contents, mediaType)
	if err != nil {
		return ProcessedImage{}, err
	}
	if err := p.validateDimensions(cfg.Width, cfg.Height); err != nil {
		return ProcessedImage{}, err
	}
	img, err := decodeAvatar(contents, mediaType)
	if err != nil {
		return ProcessedImage{}, err
	}
	bounds := img.Bounds()
	width, height := bounds.Dx(), bounds.Dy()
	if err := p.validateDimensions(width, height); err != nil {
		return ProcessedImage{}, err
	}
	if requireSquare && width != height {
		return ProcessedImage{}, ErrUserImageNotSquare
	}
	if !requireSquare && width != height {
		img = centerCropSquare(img)
	}
	result := ProcessedImage{
		SourceMediaType: mediaType,
		OriginalWidth:   width,
		OriginalHeight:  height,
		SHA256:          sha256Bytes(contents),
		Variants:        make(map[int][]byte, len(VariantSizes)),
	}
	for _, size := range VariantSizes {
		variant, err := encodeVariant(img, size, p.Quality)
		if err != nil {
			return ProcessedImage{}, fmt.Errorf("encoding %dpx avatar variant: %w", size, err)
		}
		result.Variants[size] = variant
	}
	return result, nil
}

func sniffAvatarMedia(contents []byte) (string, error) {
	if len(contents) >= 3 && contents[0] == 0xff && contents[1] == 0xd8 && contents[2] == 0xff {
		return "image/jpeg", nil
	}
	if len(contents) >= 8 && bytes.Equal(contents[:8], []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}) {
		return "image/png", nil
	}
	if len(contents) >= 12 && string(contents[:4]) == "RIFF" && string(contents[8:12]) == "WEBP" {
		if bytes.Contains(contents[12:], []byte("ANIM")) {
			return "", ErrAnimatedWebP
		}
		return "image/webp", nil
	}
	return "", ErrUnsupportedMedia
}

func decodeAvatarConfig(contents []byte, mediaType string) (image.Config, error) {
	switch mediaType {
	case "image/webp":
		cfg, err := webp.DecodeConfig(bytes.NewReader(contents))
		if err != nil {
			return image.Config{}, fmt.Errorf("reading WebP avatar dimensions: %w", err)
		}
		return cfg, nil
	case "image/jpeg", "image/png":
		cfg, _, err := image.DecodeConfig(bytes.NewReader(contents))
		if err != nil {
			return image.Config{}, fmt.Errorf("reading avatar image dimensions: %w", err)
		}
		return cfg, nil
	default:
		return image.Config{}, ErrUnsupportedMedia
	}
}

func decodeAvatar(contents []byte, mediaType string) (image.Image, error) {
	switch mediaType {
	case "image/webp":
		anim, err := webp.DecodeAll(bytes.NewReader(contents))
		if err != nil {
			return nil, fmt.Errorf("decoding WebP avatar: %w", err)
		}
		if len(anim.Image) != 1 {
			return nil, ErrAnimatedWebP
		}
		return anim.Image[0], nil
	case "image/jpeg", "image/png":
		img, _, err := image.Decode(bytes.NewReader(contents))
		if err != nil {
			return nil, fmt.Errorf("decoding avatar image: %w", err)
		}
		return img, nil
	default:
		return nil, ErrUnsupportedMedia
	}
}

func (p Processor) validateDimensions(width, height int) error {
	if width <= 0 || height <= 0 || width > p.MaxDimension || height > p.MaxDimension {
		return ErrInvalidDimensions
	}
	if width > math.MaxInt/height || width*height > p.MaxPixels {
		return ErrInvalidDimensions
	}
	return nil
}

func centerCropSquare(src image.Image) image.Image {
	b := src.Bounds()
	width, height := b.Dx(), b.Dy()
	side := width
	if height < side {
		side = height
	}
	x0 := b.Min.X + (width-side)/2
	y0 := b.Min.Y + (height-side)/2
	dst := image.NewRGBA(image.Rect(0, 0, side, side))
	draw.Draw(dst, dst.Bounds(), src, image.Pt(x0, y0), draw.Src)
	return dst
}

func encodeVariant(src image.Image, size int, quality int) ([]byte, error) {
	dst := image.NewRGBA(image.Rect(0, 0, size, size))
	draw.CatmullRom.Scale(dst, dst.Bounds(), src, src.Bounds(), draw.Over, nil)
	var buf bytes.Buffer
	if err := webp.Encode(&buf, dst, webp.Options{Quality: quality, Method: webp.DefaultMethod}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func sha256Bytes(contents []byte) []byte {
	sum := sha256.Sum256(contents)
	out := make([]byte, len(sum))
	copy(out, sum[:])
	return out
}
