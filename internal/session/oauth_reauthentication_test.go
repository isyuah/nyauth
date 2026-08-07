package session

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestOAuthReauthenticationStateIsSingleUseAndSecretKeyed(t *testing.T) {
	store, mini := testStore(t)
	data := &OAuthReauthenticationData{RequestURI: "/authorize?client_id=client", CreatedAt: time.Now().UTC()}
	if err := store.SaveOAuthReauthentication(context.Background(), "raw-continuation", data, time.Minute); err != nil {
		t.Fatal(err)
	}
	for _, key := range mini.Keys() {
		if key == oauthReauthenticationPrefix+"raw-continuation" {
			t.Fatal("raw continuation token was used as a Redis key")
		}
	}
	consumed, err := store.ConsumeOAuthReauthentication(context.Background(), "raw-continuation")
	if err != nil || consumed.RequestURI != data.RequestURI {
		t.Fatalf("consumed=%#v err=%v", consumed, err)
	}
	if _, err := store.ConsumeOAuthReauthentication(context.Background(), "raw-continuation"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second consume error=%v", err)
	}
}
