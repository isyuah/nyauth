package avatar

import (
	"context"
	"io"

	"github.com/google/uuid"
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

// StoreRef identifies the immutable storage profile used for one avatar. A nil
// profile ID is the deployment-configured fallback store.
type StoreRef struct {
	ProfileID *uuid.UUID
	Store     BlobStore
}

type StoreResolver interface {
	Current(context.Context) (StoreRef, error)
	Resolve(context.Context, *uuid.UUID, StorageBackend) (BlobStore, error)
}

type StaticStoreResolver struct{ Store BlobStore }

func (r StaticStoreResolver) Current(context.Context) (StoreRef, error) {
	if r.Store == nil {
		return StoreRef{}, ErrStorageUnavailable
	}
	return StoreRef{Store: r.Store}, nil
}

func (r StaticStoreResolver) Resolve(_ context.Context, profileID *uuid.UUID, backend StorageBackend) (BlobStore, error) {
	if r.Store == nil || profileID != nil || r.Store.Backend() != backend {
		return nil, ErrStorageUnavailable
	}
	return r.Store, nil
}
