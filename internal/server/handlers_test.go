package server

import (
	"net/http/httptest"
	"testing"
)

func TestSessionResponsesDisableCaching(t *testing.T) {
	t.Parallel()
	recorder := httptest.NewRecorder()
	setSessionNoStoreHeaders(recorder)
	if got := recorder.Header().Get("Cache-Control"); got != "no-store, private" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := recorder.Header().Get("Pragma"); got != "no-cache" {
		t.Fatalf("Pragma = %q", got)
	}
}
