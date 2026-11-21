package software

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const cacheTTL = 15 * time.Minute

// Release is one downloadable file from the newest published GitHub release.
type Release struct {
	Tag  string
	Name string
	URL  string
	Size int64
}

// Payload is the upstream file ready to stream to the browser.
type Payload struct {
	Status        int
	ContentLength int64
	ContentRange  string
	Source        string
	Body          io.ReadCloser
}

type assetRule struct {
	repo  string
	match func(name string) bool
}

// stable public filenames served by the panel.
var rules = map[string]assetRule{
	"v2rayNG-arm64-v8a.apk": {
		repo: "2dust/v2rayNG",
		match: func(name string) bool {
			return strings.HasSuffix(name, "_arm64-v8a.apk") && !strings.Contains(name, "fdroid")
		},
	},
	"v2rayNG-armeabi-v7a.apk": {
		repo: "2dust/v2rayNG",
		match: func(name string) bool {
			return strings.HasSuffix(name, "_armeabi-v7a.apk") && !strings.Contains(name, "fdroid")
		},
	},
	"v2rayN.zip": {
		repo:  "2dust/v2rayN",
		match: func(name string) bool { return name == "v2rayN-windows-64.zip" },
	},
	"v2rayN-linux-64.zip": {
		repo:  "2dust/v2rayN",
		match: func(name string) bool { return name == "v2rayN-linux-64.zip" },
	},
	"v2rayN-macos-arm64.dmg": {
		repo:  "2dust/v2rayN",
		match: func(name string) bool { return name == "v2rayN-macos-arm64.dmg" },
	},
	"v2rayN-macos-64.dmg": {
		repo:  "2dust/v2rayN",
		match: func(name string) bool { return name == "v2rayN-macos-64.dmg" },
	},
}

// Proxy resolves the newest GitHub release and streams it.
// The browser keeps the panel URL; this process copies the bytes.
type Proxy struct {
	client  *http.Client
	now     func() time.Time
	apiBase string

	mu    sync.Mutex
	cache map[string]cachedRelease
}

type cachedRelease struct {
	at      time.Time
	release githubRelease
}

type githubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

func NewProxy() *Proxy {
	return &Proxy{
		client:  &http.Client{Transport: &http.Transport{ResponseHeaderTimeout: 30 * time.Second}},
		now:     time.Now,
		apiBase: "https://api.github.com",
		cache:   map[string]cachedRelease{},
	}
}

func (p *Proxy) Known(name string) bool {
	_, ok := rules[name]
	return ok
}

func (p *Proxy) Resolve(ctx context.Context, filename string) (Release, error) {
	rule, ok := rules[filename]
	if !ok {
		return Release{}, fmt.Errorf("unknown software %q", filename)
	}
	release, err := p.latest(ctx, rule.repo)
	if err != nil {
		return Release{}, err
	}
	for _, asset := range release.Assets {
		if rule.match(asset.Name) {
			return Release{Tag: release.TagName, Name: asset.Name, URL: asset.BrowserDownloadURL, Size: asset.Size}, nil
		}
	}
	return Release{}, fmt.Errorf("release %s has no file for %s", release.TagName, filename)
}

func (p *Proxy) Open(ctx context.Context, filename, rangeHeader string) (*Payload, error) {
	release, err := p.Resolve(ctx, filename)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, release.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ppanel-software-proxy")
	if rangeHeader != "" {
		req.Header.Set("Range", rangeHeader)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		resp.Body.Close()
		return nil, fmt.Errorf("github download status %d", resp.StatusCode)
	}
	return &Payload{
		Status:        resp.StatusCode,
		ContentLength: resp.ContentLength,
		ContentRange:  resp.Header.Get("Content-Range"),
		Source:        release.Tag + ":" + release.Name,
		Body:          resp.Body,
	}, nil
}

func (p *Proxy) latest(ctx context.Context, repo string) (githubRelease, error) {
	p.mu.Lock()
	if cached, ok := p.cache[repo]; ok && p.now().Sub(cached.at) < cacheTTL {
		p.mu.Unlock()
		return cached.release, nil
	}
	p.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.apiBase+"/repos/"+repo+"/releases?per_page=1", nil)
	if err != nil {
		return githubRelease{}, err
	}
	req.Header.Set("User-Agent", "ppanel-software-proxy")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := p.client.Do(req)
	if err != nil {
		return githubRelease{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return githubRelease{}, fmt.Errorf("github releases status %d", resp.StatusCode)
	}
	var releases []githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return githubRelease{}, err
	}
	if len(releases) == 0 {
		return githubRelease{}, fmt.Errorf("github repo %s has no releases", repo)
	}
	p.mu.Lock()
	p.cache[repo] = cachedRelease{at: p.now(), release: releases[0]}
	p.mu.Unlock()
	return releases[0], nil
}
