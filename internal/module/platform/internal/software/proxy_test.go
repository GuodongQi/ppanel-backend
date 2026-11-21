package software

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestResolveNewestReleaseAsset(t *testing.T) {
	proxy := NewProxy()
	proxy.now = func() time.Time { return time.Unix(0, 0) }
	proxy.cache["2dust/v2rayNG"] = cachedRelease{
		at: time.Unix(0, 0),
		release: githubRelease{
			TagName: "2.4.0",
			Assets: []githubAsset{
				{Name: "v2rayNG_2.4.0-fdroid_arm64-v8a.apk", BrowserDownloadURL: "https://example.invalid/fdroid", Size: 1},
				{Name: "v2rayNG_2.4.0_arm64-v8a.apk", BrowserDownloadURL: "https://example.invalid/official", Size: 32},
			},
		},
	}

	got, err := proxy.Resolve(context.Background(), "v2rayNG-arm64-v8a.apk")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "v2rayNG_2.4.0_arm64-v8a.apk" || got.Tag != "2.4.0" || got.Size != 32 {
		t.Fatalf("resolved %+v", got)
	}
}

func TestOpenStreamsReleaseBytes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "bytes=0-3" {
			t.Fatalf("range %q", r.Header.Get("Range"))
		}
		w.Header().Set("Content-Range", "bytes 0-3/8")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = io.WriteString(w, "PK\x03\x04")
	}))
	defer server.Close()

	proxy := NewProxy()
	proxy.client = server.Client()
	proxy.now = time.Now
	proxy.cache["2dust/v2rayNG"] = cachedRelease{
		at: time.Now(),
		release: githubRelease{
			TagName: "2.4.0",
			Assets: []githubAsset{{
				Name:               "v2rayNG_2.4.0_arm64-v8a.apk",
				BrowserDownloadURL: server.URL + "/apk",
				Size:               8,
			}},
		},
	}

	payload, err := proxy.Open(context.Background(), "v2rayNG-arm64-v8a.apk", "bytes=0-3")
	if err != nil {
		t.Fatal(err)
	}
	defer payload.Body.Close()
	body, err := io.ReadAll(payload.Body)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Status != http.StatusPartialContent || string(body) != "PK\x03\x04" || payload.Source != "2.4.0:v2rayNG_2.4.0_arm64-v8a.apk" {
		t.Fatalf("payload status=%d body=%q source=%s", payload.Status, body, payload.Source)
	}
}

func TestLatestUsesFirstPublishedRelease(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/2dust/v2rayNG/releases" || r.URL.Query().Get("per_page") != "1" {
			t.Fatalf("request %s", r.URL.RequestURI())
		}
		_, _ = io.WriteString(w, `[{"tag_name":"2.4.0","assets":[{"name":"v2rayNG_2.4.0_arm64-v8a.apk","browser_download_url":"https://example.invalid/apk","size":8}]}]`)
	}))
	defer server.Close()

	proxy := NewProxy()
	proxy.client = server.Client()
	proxy.apiBase = server.URL
	got, err := proxy.Resolve(context.Background(), "v2rayNG-arm64-v8a.apk")
	if err != nil {
		t.Fatal(err)
	}
	if got.Tag != "2.4.0" || got.Name != "v2rayNG_2.4.0_arm64-v8a.apk" {
		t.Fatalf("resolved %+v", got)
	}
}

func TestUnknownNameIsRejected(t *testing.T) {
	if _, err := NewProxy().Resolve(context.Background(), "../ppanel.yaml"); err == nil {
		t.Fatal("expected unknown software to be rejected")
	}
}
