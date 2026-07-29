package avatar

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/pkg/models"
)

const (
	MaxUploadBytes = 8 << 20
	MaxDimension   = 4096
	MaxPixels      = 16_777_216
	WebPQuality    = 85
	ContentType    = "image/webp"
)

var VariantSizes = models.AvatarVariantSizes

var (
	ErrImageTooLarge      = errors.New("avatar image exceeds 8 MiB")
	ErrUnsupportedMedia   = errors.New("avatar media type must be JPEG, PNG, or static WebP")
	ErrAnimatedWebP       = errors.New("animated WebP avatars are not supported")
	ErrInvalidDimensions  = errors.New("avatar image dimensions are invalid")
	ErrUserImageNotSquare = errors.New("user avatar upload must be square after browser crop")
	ErrNotFound           = errors.New("avatar not found")
	ErrAvatarAlreadySet   = errors.New("user already has an avatar")
	ErrStorageUnavailable = errors.New("avatar storage profile is unavailable")
)

type Source = models.AvatarSource
type StorageBackend = models.AvatarStorageBackend

const (
	SourceUserUpload     = models.AvatarSourceUserUpload
	SourceAdminUpload    = models.AvatarSourceAdminUpload
	SourceProviderImport = models.AvatarSourceProviderImport
	StorageLocal         = models.AvatarStorageLocal
	StorageS3            = models.AvatarStorageS3
)

type ProcessedImage struct {
	SourceMediaType string
	OriginalWidth   int
	OriginalHeight  int
	SHA256          []byte
	Variants        map[int][]byte
}

type StoredVariant struct {
	Size      int
	ObjectKey string
	Bytes     int64
}

type ActiveVariant struct {
	StorageBackend   StorageBackend
	StorageProfileID *uuid.UUID
	Variant          models.AvatarVariant
}

type CreateAvatarParams struct {
	ID                uuid.UUID
	UserID            uuid.UUID
	Source            Source
	StorageBackend    StorageBackend
	StorageProfileID  *uuid.UUID
	ObjectPrefix      string
	Variants          []models.AvatarVariant
	ContentSHA256     []byte
	OriginalMediaType string
	OriginalWidth     int
	OriginalHeight    int
}

func objectKey(prefix string, size int) string {
	return fmt.Sprintf("%s/%d.webp", prefix, size)
}
