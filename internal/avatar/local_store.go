package avatar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type LocalStore struct {
	root string
}

func NewLocalStore(root string) (*LocalStore, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, fmt.Errorf("local avatar media root is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolving local avatar media root: %w", err)
	}
	if err := os.MkdirAll(abs, 0o750); err != nil {
		return nil, fmt.Errorf("creating local avatar media root: %w", err)
	}
	return &LocalStore{root: abs}, nil
}

func (s *LocalStore) Backend() StorageBackend { return StorageLocal }

func (s *LocalStore) Put(ctx context.Context, key string, contents []byte, contentType string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	target, err := s.resolve(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		return fmt.Errorf("creating avatar media directory: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(target), ".nyauth-avatar-*")
	if err != nil {
		return fmt.Errorf("creating avatar media temp file: %w", err)
	}
	tempName := temp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tempName)
		}
	}()
	if _, err := io.Copy(temp, bytes.NewReader(contents)); err != nil {
		_ = temp.Close()
		return fmt.Errorf("writing avatar media temp file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("syncing avatar media temp file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("closing avatar media temp file: %w", err)
	}
	if err := os.Rename(tempName, target); err != nil {
		return fmt.Errorf("committing avatar media file: %w", err)
	}
	cleanup = false
	return nil
}

func (s *LocalStore) Get(ctx context.Context, key string) (BlobObject, error) {
	if err := ctx.Err(); err != nil {
		return BlobObject{}, err
	}
	target, err := s.resolve(key)
	if err != nil {
		return BlobObject{}, err
	}
	file, err := os.Open(target)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return BlobObject{}, ErrNotFound
		}
		return BlobObject{}, fmt.Errorf("opening avatar media file: %w", err)
	}
	stat, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return BlobObject{}, fmt.Errorf("stat avatar media file: %w", err)
	}
	return BlobObject{Body: file, Size: stat.Size(), ContentType: ContentType}, nil
}

func (s *LocalStore) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	target, err := s.resolve(key)
	if err != nil {
		return err
	}
	if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("deleting avatar media file: %w", err)
	}
	return nil
}

func (s *LocalStore) resolve(key string) (string, error) {
	key = strings.TrimSpace(strings.ReplaceAll(key, "\\", "/"))
	if key == "" || strings.HasPrefix(key, "/") || strings.Contains(key, "../") || key == ".." || strings.ContainsRune(key, 0) {
		return "", fmt.Errorf("invalid avatar media object key")
	}
	clean := filepath.Clean(filepath.FromSlash(key))
	target := filepath.Join(s.root, clean)
	rel, err := filepath.Rel(s.root, target)
	if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || rel == ".." || filepath.IsAbs(rel) {
		return "", fmt.Errorf("avatar media object key escapes storage root")
	}
	return target, nil
}
