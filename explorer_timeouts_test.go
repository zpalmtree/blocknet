package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestExplorerHTTPServer_HasTimeoutsAndCutsSlowloris(t *testing.T) {
	e := &Explorer{
		// Avoid NewExplorer() here: it starts background stats goroutines that
		// require a fully wired daemon/chain/mempool.
		mux: http.NewServeMux(),
	}
	e.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := e.httpServer("127.0.0.1:0")
	if srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Fatalf("expected non-zero timeouts (read=%s write=%s idle=%s)", srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout)
	}
	if srv.ReadTimeout != 10*time.Second || srv.WriteTimeout != 30*time.Second || srv.IdleTimeout != 60*time.Second {
		t.Fatalf("unexpected timeout defaults (read=%s write=%s idle=%s)", srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout)
	}

	// For the slowloris behavior check, reduce timeouts so the test is fast.
	srv.ReadTimeout = 100 * time.Millisecond
	srv.WriteTimeout = 200 * time.Millisecond
	srv.IdleTimeout = 200 * time.Millisecond

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() {
		// http.Server.Serve closes the listener; Close may return net.ErrClosed.
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close listener: %v", err)
		}
	}()

	go func() {
		_ = srv.Serve(ln)
	}()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close conn: %v", err)
		}
	}()

	// Send an intentionally incomplete request so the server stays in header-read.
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: example\r\n"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	// After ReadTimeout, server should close the connection.
	time.Sleep(250 * time.Millisecond)

	_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatalf("expected read error/EOF after read timeout, got nil")
	}
}

