package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// flakyImageServer serves payload as /image.tar (honouring Range) and its
// checksum as /image.tar.sha256. The first full-body response is cut off
// halfway, the way a timed-out link drops a download.
func flakyImageServer(t *testing.T, payload []byte, checksum string) (srv *httptest.Server, imageRequests *int32) {
	t.Helper()
	var requests int32
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/image.tar.sha256":
			fmt.Fprintf(w, "%s  image.tar\n", checksum)
		case "/image.tar":
			n := atomic.AddInt32(&requests, 1)
			start := 0
			if rng := r.Header.Get("Range"); rng != "" {
				start, _ = strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(rng, "bytes="), "-"))
				w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, len(payload)-1, len(payload)))
				w.Header().Set("Content-Length", strconv.Itoa(len(payload)-start))
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write(payload[start:])
				return
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
			if n == 1 {
				_, _ = w.Write(payload[:len(payload)/2])
				// Abort the connection mid-body.
				panic(http.ErrAbortHandler)
			}
			_, _ = w.Write(payload)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &requests
}

func TestDownloadV2RayImageResumes(t *testing.T) {
	payload := []byte(strings.Repeat("sing-box-layer-data ", 5000))
	sum := sha256.Sum256(payload)
	srv, requests := flakyImageServer(t, payload, hex.EncodeToString(sum[:]))

	got, err := downloadV2RayImage(context.Background(), srv.URL+"/image.tar")
	if err != nil {
		t.Fatalf("downloadV2RayImage: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("downloaded %d bytes, want %d identical bytes", len(got), len(payload))
	}
	if n := atomic.LoadInt32(requests); n != 2 {
		t.Fatalf("image requests = %d, want 2 (cut off, then resumed)", n)
	}
}

func TestDownloadV2RayImageRejectsBadChecksum(t *testing.T) {
	srv, _ := flakyImageServer(t, []byte("payload"), strings.Repeat("0", 64))
	if _, err := downloadV2RayImage(context.Background(), srv.URL+"/image.tar"); err == nil ||
		!strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("err = %v, want a checksum mismatch", err)
	}
}

func TestV2RayArchSuffix(t *testing.T) {
	for arch, want := range map[string]string{"arm64": "arm64", "arm": "armv7", "x86_64": "amd64"} {
		if got, err := v2rayArchSuffix(arch); err != nil || got != want {
			t.Errorf("v2rayArchSuffix(%q) = %q, %v; want %q", arch, got, err, want)
		}
	}
	if _, err := v2rayArchSuffix("mipsbe"); err == nil {
		t.Error("v2rayArchSuffix(mipsbe) succeeded, want an error")
	}
}
