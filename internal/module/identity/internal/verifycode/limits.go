package verifycode

import (
	"context"

	"github.com/perfect-panel/server/internal/auth/ratelimit"
	"github.com/perfect-panel/server/pkg/requestmeta"
	"github.com/perfect-panel/server/pkg/xerr"
)

// Every code costs a delivery, and an SMS costs money. The per-address
// quotas alone do not bound a client that rotates addresses, so each client
// address also gets CodesPerIPPerHour codes an hour, whatever the addresses:
// enough for a person retrying a form or binding several addresses, far too
// few for a bombing or pumping script. An unknown address shares one quota.
const (
	CodesPerIPPerHour = 20
	ipQuotaKeyPrefix  = "auth:verify_code_ip:"
)

// takeIPPermit charges one code to the client address's hourly quota.
func (s *Service) takeIPPermit(ctx context.Context) error {
	if s.deps.Redis == nil {
		return nil
	}
	meta, _ := requestmeta.From(ctx)
	ip := meta.ClientIP
	if ip == "" {
		ip = "unknown"
	}
	limiter := ratelimit.NewPeriodLimit(3600, CodesPerIPPerHour, s.deps.Redis, ipQuotaKeyPrefix)
	permit, err := limiter.Take(ctx, ip)
	if err != nil {
		return xerr.Wrapf(err, xerr.ERROR, "take the per-address send permit")
	}
	if !limiter.ParsePermitState(permit) {
		return xerr.Errorf(xerr.TooManyRequests, "too many verification codes requested from this address")
	}
	return nil
}
