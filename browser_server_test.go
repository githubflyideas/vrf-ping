package main

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

// TestBrowserServer serves the real router, login and CSP included, on a
// random loopback port for login_capslock.test.cjs. It is skipped unless
// that test starts it, and stops when signalled (or after 5 minutes).
func TestBrowserServer(t *testing.T) {
	if os.Getenv("BROWSER_TEST_SERVE") == "" {
		t.Skip("started by login_capslock.test.cjs")
	}
	srv := httptest.NewServer(newMux(defaultConfig(), nil, map[string]string{"admin": "browser-test-password"}))
	defer srv.Close()
	fmt.Println("BROWSER_TEST_URL=" + srv.URL)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	<-ctx.Done()
}
