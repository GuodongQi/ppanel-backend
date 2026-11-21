package software

import (
	"context"
	"net/http"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/perfect-panel/server/internal/module/platform/internal/software"
)

var downloader = software.NewProxy()

// DownloadHandler streams the newest GitHub release for a stable panel filename.
// The browser never follows a redirect to GitHub.
func DownloadHandler() app.HandlerFunc {
	return func(c context.Context, ctx *app.RequestContext) {
		name := ctx.Param("name")
		if string(ctx.Method()) == http.MethodHead {
			release, err := downloader.Resolve(c, name)
			if err != nil {
				status := http.StatusBadGateway
				if !downloader.Known(name) {
					status = http.StatusNotFound
				}
				ctx.SetStatusCode(status)
				return
			}
			ctx.SetStatusCode(http.StatusOK)
			ctx.Response.Header.Set("Content-Type", "application/octet-stream")
			ctx.Response.Header.Set("Content-Disposition", "attachment; filename=\""+name+"\"")
			ctx.Response.Header.Set("Cache-Control", "no-cache")
			ctx.Response.Header.Set("X-Software-Source", "github:"+release.Tag+":"+release.Name)
			ctx.Response.Header.Set("Accept-Ranges", "bytes")
			ctx.Response.Header.SetContentLength(int(release.Size))
			return
		}
		payload, err := downloader.Open(c, name, string(ctx.GetHeader("Range")))
		if err != nil {
			status := http.StatusBadGateway
			if !downloader.Known(name) {
				status = http.StatusNotFound
			}
			ctx.SetStatusCode(status)
			ctx.SetBodyString(http.StatusText(status))
			return
		}
		ctx.SetStatusCode(payload.Status)
		ctx.Response.Header.Set("Content-Type", "application/octet-stream")
		ctx.Response.Header.Set("Content-Disposition", "attachment; filename=\""+name+"\"")
		ctx.Response.Header.Set("Cache-Control", "no-cache")
		ctx.Response.Header.Set("X-Software-Source", "github:"+payload.Source)
		ctx.Response.Header.Set("Accept-Ranges", "bytes")
		if payload.ContentRange != "" {
			ctx.Response.Header.Set("Content-Range", payload.ContentRange)
		}
		size := int(payload.ContentLength)
		if payload.ContentLength < 0 {
			size = -1
		}
		ctx.SetBodyStream(payload.Body, size)
	}
}
