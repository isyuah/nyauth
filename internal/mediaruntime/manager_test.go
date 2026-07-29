package mediaruntime

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/nyasharp/nyauth/internal/avatar"
	"github.com/nyasharp/nyauth/pkg/models"
)

type memoryBlobStore struct {
	objects      map[string][]byte
	corruptReads bool
}

func (s *memoryBlobStore) Backend() avatar.StorageBackend { return avatar.StorageS3 }
func (s *memoryBlobStore) Put(_ context.Context, key string, body []byte, _ string) error {
	if s.objects == nil {
		s.objects = map[string][]byte{}
	}
	s.objects[key] = append([]byte(nil), body...)
	return nil
}
func (s *memoryBlobStore) Get(_ context.Context, key string) (avatar.BlobObject, error) {
	body, ok := s.objects[key]
	if !ok {
		return avatar.BlobObject{}, avatar.ErrNotFound
	}
	body = append([]byte(nil), body...)
	if s.corruptReads && len(body) > 0 {
		body[0] ^= 0xff
	}
	return avatar.BlobObject{Body: io.NopCloser(bytes.NewReader(body)), Size: int64(len(body)), ContentType: avatar.ContentType}, nil
}
func (s *memoryBlobStore) Delete(_ context.Context, key string) error {
	delete(s.objects, key)
	return nil
}

func TestCopyAndVerifyVariantsRejectsCorruptTarget(t *testing.T) {
	source := &memoryBlobStore{objects: map[string][]byte{"avatars/a/64.webp": []byte("valid-avatar")}}
	target := &memoryBlobStore{corruptReads: true}
	variants := []models.AvatarVariant{{Size: 64, ObjectKey: "avatars/a/64.webp", ContentType: avatar.ContentType, Bytes: int64(len("valid-avatar"))}}
	if err := copyAndVerifyVariants(context.Background(), source, target, variants); err == nil {
		t.Fatal("corrupt target unexpectedly passed verification")
	}
}

func TestCopyAndVerifyVariantsCopiesExactBytes(t *testing.T) {
	source := &memoryBlobStore{objects: map[string][]byte{"avatars/a/64.webp": []byte("small"), "avatars/a/128.webp": []byte("larger-avatar")}}
	target := &memoryBlobStore{}
	variants := []models.AvatarVariant{{Size: 64, ObjectKey: "avatars/a/64.webp", ContentType: avatar.ContentType, Bytes: 5}, {Size: 128, ObjectKey: "avatars/a/128.webp", ContentType: avatar.ContentType, Bytes: 13}}
	if err := copyAndVerifyVariants(context.Background(), source, target, variants); err != nil {
		t.Fatalf("copyAndVerifyVariants() error=%v", err)
	}
	for key, want := range source.objects {
		if got := target.objects[key]; !bytes.Equal(got, want) {
			t.Fatalf("target[%q]=%q want %q", key, got, want)
		}
	}
}
