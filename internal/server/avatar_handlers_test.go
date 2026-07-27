package server

import (
	"net/http/httptest"
	"testing"
)

func TestReserveAvatarProcessingBoundsConcurrentImageWork(t *testing.T) {
	s := &Server{avatarProcessing: make(chan struct{}, 1)}
	request := httptest.NewRequest("POST", "/api/me/avatar", nil)
	firstRecorder := httptest.NewRecorder()
	release, ok := s.reserveAvatarProcessing(firstRecorder, request)
	if !ok {
		t.Fatal("first processing slot was rejected")
	}

	busyRecorder := httptest.NewRecorder()
	if _, ok := s.reserveAvatarProcessing(busyRecorder, request); ok {
		t.Fatal("second concurrent processing slot was accepted")
	}
	if busyRecorder.Code != 503 || busyRecorder.Header().Get("Retry-After") != "2" {
		t.Fatalf("busy response status=%d retry_after=%q", busyRecorder.Code, busyRecorder.Header().Get("Retry-After"))
	}

	release()
	thirdRecorder := httptest.NewRecorder()
	thirdRelease, ok := s.reserveAvatarProcessing(thirdRecorder, request)
	if !ok {
		t.Fatal("processing slot was not released")
	}
	thirdRelease()
}
