package realityscan

import (
	"context"

	"github.com/hibiken/asynq"
	"github.com/perfect-panel/server/pkg/logger"
)

// Scanner starts the scheduled Reality camouflage scan when it is due.
type Scanner interface {
	RunScheduledRealityScan(ctx context.Context) error
}

// Handler is the periodic tick for that scan.
type Handler struct {
	scanner Scanner
}

// NewHandler builds the tick over scanner.
func NewHandler(scanner Scanner) *Handler {
	return &Handler{scanner: scanner}
}

// ProcessTask runs the scan when today's configured time has passed.
func (h *Handler) ProcessTask(ctx context.Context, _ *asynq.Task) error {
	if h.scanner == nil {
		return nil
	}
	if err := h.scanner.RunScheduledRealityScan(ctx); err != nil {
		logger.WithContext(ctx).Errorw("[RealityScan] scheduled scan failed", logger.Field("error", err.Error()))
		return err
	}
	return nil
}
