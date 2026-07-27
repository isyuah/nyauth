package avatar

import (
	"context"
	"io"
)

type BlobObject struct {
	Body        io.ReadCloser
	Size        int64
	ContentType string
}

type BlobStore interface {
	Backend() StorageBackend
	Put(ctx context.Context, key string, contents []byte, contentType string) error
	Get(ctx context.Context, key string) (BlobObject, error)
	Delete(ctx context.Context, key string) error
}
