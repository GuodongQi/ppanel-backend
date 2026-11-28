package server

import (
	"context"

	"github.com/cloudwego/hertz/pkg/app"
	dto "github.com/perfect-panel/server/internal/module/network/contract"
	"github.com/perfect-panel/server/pkg/httpx"
)

// RealityScanner is the admin surface of the Reality camouflage scan.
type RealityScanner interface {
	GetRealityScan(ctx context.Context) (dto.RealityScanView, error)
	UpdateRealityScan(ctx context.Context, cfg dto.RealityScanConfig) (dto.RealityScanView, error)
	RunRealityScan(ctx context.Context) (dto.RealityScanView, error)
}

// GetRealityScanHandler documents Get Reality Scan.
//
// @Summary Get Reality Scan
// @Tags admin
// @Produce json
// @Security BearerAuth
// @Success 200 {object} httpx.ResponseSuccessBean
// @Router /v1/admin/reality-scan [get]
func GetRealityScanHandler(service RealityScanner) app.HandlerFunc {
	return func(c context.Context, ctx *app.RequestContext) {
		view, err := service.GetRealityScan(c)
		httpx.HttpResult(ctx, view, err)
	}
}

// UpdateRealityScanHandler documents Update Reality Scan.
//
// @Summary Update Reality Scan
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.RealityScanConfig true "Request parameters"
// @Success 200 {object} httpx.ResponseSuccessBean
// @Router /v1/admin/reality-scan [put]
func UpdateRealityScanHandler(service RealityScanner) app.HandlerFunc {
	return func(c context.Context, ctx *app.RequestContext) {
		var req dto.RealityScanConfig
		if err := httpx.ShouldBind(ctx, &req); err != nil {
			httpx.ParamErrorResult(ctx, err)
			return
		}
		view, err := service.UpdateRealityScan(c, req)
		httpx.HttpResult(ctx, view, err)
	}
}

// RunRealityScanHandler documents Run Reality Scan.
//
// @Summary Run Reality Scan
// @Tags admin
// @Produce json
// @Security BearerAuth
// @Success 200 {object} httpx.ResponseSuccessBean
// @Router /v1/admin/reality-scan/run [post]
func RunRealityScanHandler(service RealityScanner) app.HandlerFunc {
	return func(c context.Context, ctx *app.RequestContext) {
		view, err := service.RunRealityScan(c)
		httpx.HttpResult(ctx, view, err)
	}
}
