package avatar

import (
	"context"
	"io"
	"testing"
)

func TestLocalStoreRejectsEscapingKeys(t *testing.T) {
	store, err := NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore() error = %v", err)
	}
	for _, key := range []string{"../avatar.webp", "/absolute/avatar.webp", `..\avatar.webp`, "avatars/../escape.webp"} {
		if err := store.Put(context.Background(), key, []byte("x"), ContentType); err == nil {
			t.Fatalf("Put(%q) unexpectedly succeeded", key)
		}
	}
}

func TestLocalStorePutGetDelete(t *testing.T) {
	store, err := NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore() error = %v", err)
	}
	ctx := context.Background()
	key := "avatars/user/avatar/64.webp"
	if err := store.Put(ctx, key, []byte("avatar"), ContentType); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	object, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	body, err := io.ReadAll(object.Body)
	closeErr := object.Body.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("reading object = %v, closing = %v", err, closeErr)
	}
	if string(body) != "avatar" || object.Size != int64(len("avatar")) || object.ContentType != ContentType {
		t.Fatalf("object = %#v body=%q", object, body)
	}
	if err := store.Delete(ctx, key); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := store.Get(ctx, key); err != ErrNotFound {
		t.Fatalf("Get() after delete error = %v", err)
	}
}
