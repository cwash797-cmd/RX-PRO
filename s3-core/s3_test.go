// SPDX-License-Identifier: MPL-2.0
package xdrive

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet"
)

func testS3(t *testing.T, handler http.HandlerFunc) (*s3Storage, *httptest.Server) {
	t.Helper()
	ts := httptest.NewTLSServer(handler)
	t.Cleanup(ts.Close)
	raw, _ := json.Marshal(s3Credentials{Endpoint: ts.URL, Region: "ru-msk", Bucket: "test-bucket", AccessKey: "TESTACCESS", SecretKey: "TESTSECRET"})
	c := &Config{Service: "S3", RemoteFolder: "private/device1", Secrets: []string{string(raw)}}
	s, err := newS3Storage(&internet.MemoryStreamConfig{ProtocolSettings: c}, c)
	if err != nil {
		t.Fatal(err)
	}
	// Unit tests trust only the test server's generated certificate.
	s.client = ts.Client()
	s.client.Timeout = 2 * time.Second
	s.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return s, ts
}
func digestString(s string) string { d := sha256.Sum256([]byte(s)); return hex.EncodeToString(d[:]) }
func mac(key []byte, s string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(s))
	return h.Sum(nil)
}

// Independent verification of AWS SDK signer output, including escaped paths.
func verifySignature(t *testing.T, r *http.Request, body []byte) {
	t.Helper()
	auth := r.Header.Get("Authorization")
	parts := strings.Split(auth, "SignedHeaders=")
	if len(parts) != 2 {
		t.Errorf("missing SigV4 header")
		return
	}
	signed := strings.Split(parts[1], ",")[0]
	headers := ""
	for _, key := range strings.Split(signed, ";") {
		value := r.Header.Get(key)
		if key == "host" {
			value = r.Host
		}
		headers += key + ":" + strings.Join(strings.Fields(value), " ") + "\n"
	}
	hash := digestString(string(body))
	if r.Header.Get("X-Amz-Content-Sha256") != hash {
		t.Error("payload hash mismatch")
	}
	canonical := r.Method + "\n" + r.URL.EscapedPath() + "\n" + strings.ReplaceAll(r.URL.Query().Encode(), "+", "%20") + "\n" + headers + "\n" + signed + "\n" + hash
	date := r.Header.Get("X-Amz-Date")
	if len(date) < 8 {
		t.Error("invalid date")
		return
	}
	scope := date[:8] + "/ru-msk/s3/aws4_request"
	key := mac([]byte("AWS4TESTSECRET"), date[:8])
	key = mac(key, "ru-msk")
	key = mac(key, "s3")
	key = mac(key, "aws4_request")
	signature := hex.EncodeToString(mac(key, "AWS4-HMAC-SHA256\n"+date+"\n"+scope+"\n"+digestString(canonical)))
	if !strings.HasSuffix(auth, "Signature="+signature) {
		t.Error("signature mismatch")
	}
}
func TestS3SigningAndScopedOperations(t *testing.T) {
	var puts atomic.Int32
	var saved []byte
	s, _ := testS3(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		verifySignature(t, r, body)
		if r.URL.Path != "/test-bucket/private/device1/streams/a/c2s/a b.seg" {
			t.Error("wrong scoped key")
		}
		switch r.Method {
		case "PUT":
			saved = append([]byte(nil), body...)
			puts.Add(1)
			w.WriteHeader(200)
		case "GET":
			w.Write(saved)
		case "DELETE":
			w.WriteHeader(204)
		default:
			t.Error("unexpected method")
		}
	})
	ctx := context.Background()
	name := "streams/a/c2s/a b.seg"
	if err := s.Put(ctx, name, []byte("data")); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, name)
	if err != nil || string(got) != "data" {
		t.Fatal("get failed", err)
	}
	if err := s.Delete(ctx, name); err != nil {
		t.Fatal(err)
	}
	if puts.Load() != 1 {
		t.Fatal("PUT count")
	}
}
func TestS3PaginationAndDirectories(t *testing.T) {
	var calls atomic.Int32
	s, _ := testS3(t, func(w http.ResponseWriter, r *http.Request) {
		verifySignature(t, r, nil)
		calls.Add(1)
		if r.URL.Query().Get("prefix") != "private/device1/streams/" || r.URL.Query().Get("delimiter") != "/" {
			t.Error("prefix/delimiter lost")
		}
		if r.URL.Query().Get("continuation-token") == "" {
			fmt.Fprint(w, `<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>next+/=</NextContinuationToken><CommonPrefixes><Prefix>private/device1/streams/a/</Prefix></CommonPrefixes></ListBucketResult>`)
		} else {
			if r.URL.Query().Get("continuation-token") != "next+/=" {
				t.Error("token encoding")
			}
			fmt.Fprint(w, `<ListBucketResult><IsTruncated>false</IsTruncated><CommonPrefixes><Prefix>private/device1/streams/b/</Prefix></CommonPrefixes></ListBucketResult>`)
		}
	})
	entries, err := s.List(context.Background(), "streams")
	if err != nil || len(entries) != 2 || entries[0].Name != "a" || entries[1].Name != "b" || calls.Load() != 2 {
		t.Fatal(entries, err)
	}
}
func TestS3FailClosedAndRedaction(t *testing.T) {
	s, ts := testS3(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		fmt.Fprint(w, "SECRET_CANONICAL_REQUEST")
	})
	err := s.Put(context.Background(), "sessions/a", nil)
	if err == nil || strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), ts.URL) {
		t.Fatal("unsafe error", err)
	}
	for _, name := range []string{"", "../a", "/a", "a/../b", "a//b", "a\\b"} {
		if s.Put(context.Background(), name, nil) == nil {
			t.Fatal("accepted unsafe key")
		}
	}
}
func TestS3RedirectNotFollowed(t *testing.T) {
	var redirected atomic.Bool
	sink := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Store(true) }))
	defer sink.Close()
	s, _ := testS3(t, func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Location", sink.URL); w.WriteHeader(307) })
	if s.Put(context.Background(), "sessions/a", nil) == nil {
		t.Fatal("redirect accepted")
	}
	if redirected.Load() {
		t.Fatal("redirect followed")
	}
}
func TestS3MissingObjectAndCancellation(t *testing.T) {
	s, _ := testS3(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) })
	if _, err := s.Get(context.Background(), "sessions/a"); err != errNotFound {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Put(ctx, "sessions/a", nil); err == nil {
		t.Fatal("cancellation ignored")
	}
}
func TestS3InvalidConfiguration(t *testing.T) {
	for _, endpoint := range []string{"http://example.com", "https://user:pass@example.com", "https://example.com/path", "https://example.com?q=1"} {
		raw, _ := json.Marshal(s3Credentials{Endpoint: endpoint, Region: "ru-msk", Bucket: "test-bucket", AccessKey: "a", SecretKey: "b"})
		cfg := &Config{Service: "S3", RemoteFolder: "private/device1", Secrets: []string{string(raw)}}
		if _, err := newS3Storage(nil, cfg); err == nil {
			t.Fatal("unsafe endpoint accepted")
		}
	}
}

func TestS3BackpressureCancellationDoesNotSpinOnClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	w := &walWriter{ctx: ctx, params: params{segmentBytes: 1}, sem: make(chan struct{}, 1), buf: []byte("x")}
	w.sem <- struct{}{}
	cancel()
	done := make(chan error, 1)
	go func() { done <- w.Close() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled close succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled writer close blocked")
	}
}
