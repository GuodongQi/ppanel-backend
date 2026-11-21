package verifycode

import (
	"context"
	"fmt"
	"testing"
	"time"

	dto "github.com/perfect-panel/server/internal/module/identity/contract"
	"github.com/perfect-panel/server/internal/module/identity/entity/auth"
	"github.com/perfect-panel/server/internal/module/identity/internal/authn/registerpolicy"
	"github.com/perfect-panel/server/internal/module/identity/internal/identitytest"
	"github.com/perfect-panel/server/pkg/logger/logtest"
	"github.com/perfect-panel/server/pkg/requestmeta"
	"github.com/perfect-panel/server/pkg/xerr"
)

// fromIP is a request context from the client address ip.
func fromIP(ip string) context.Context {
	return requestmeta.With(context.Background(), requestmeta.New(ip, identitytest.UserAgent))
}

// One client address gets a bounded number of codes an hour, whatever the
// addresses and numbers it names, so rotating targets does not get around
// the per-target quotas: a bombing or pumping script is cut off, while
// another address keeps its own quota and the quota returns with the next
// hour. Email and SMS codes share it.
func TestCodesAreCappedPerClientAddress(t *testing.T) {
	f := newCodeFixture(t)
	script := fromIP("198.51.100.7")

	for i := 0; i < CodesPerIPPerHour; i++ {
		var err error
		if i%2 == 0 {
			_, err = f.svc.SendEmailCode(script, &dto.SendCodeRequest{Email: fmt.Sprintf("target-%d@example.com", i), Type: uint8(auth.Register)})
		} else {
			_, err = f.svc.SendSmsCode(script, &dto.SendSmsCodeRequest{Type: uint8(auth.Register), TelephoneAreaCode: "86", Telephone: fmt.Sprintf("1380013%04d", i)})
		}
		if err != nil {
			t.Fatalf("code %d: %v", i, err)
		}
	}
	_, err := f.svc.SendEmailCode(script, &dto.SendCodeRequest{Email: "one-more@example.com", Type: uint8(auth.Register)})
	assertCode(t, err, xerr.TooManyRequests)
	_, err = f.svc.SendSmsCode(script, &dto.SendSmsCodeRequest{Type: uint8(auth.Register), TelephoneAreaCode: "86", Telephone: "13900139000"})
	assertCode(t, err, xerr.TooManyRequests)
	if len(f.queue.tasks) != CodesPerIPPerHour {
		t.Fatalf("deliveries = %d, want exactly the quota", len(f.queue.tasks))
	}

	if _, err := f.svc.SendEmailCode(fromIP("203.0.113.9"), &dto.SendCodeRequest{Email: "one-more@example.com", Type: uint8(auth.Register)}); err != nil {
		t.Fatalf("another address's code: %v", err)
	}
	f.Mini.FastForward(time.Hour + time.Second)
	if _, err := f.svc.SendEmailCode(script, &dto.SendCodeRequest{Email: "next-hour@example.com", Type: uint8(auth.Register)}); err != nil {
		t.Fatalf("code in the next hour: %v", err)
	}
}

// The published registration page requests the code before Turnstile is
// completed, so the code itself is not the challenge. Creating the account
// still requires the token.
func TestRegistrationCodesDoNotWaitForTheChallenge(t *testing.T) {
	logtest.Discard(t)
	env := identitytest.New(t)
	queue := &taskRecorder{}
	policy := registerpolicy.Snapshot{EmailEnabled: true, MobileEnabled: true, RegisterVerify: true, TurnstileSecret: "site-secret"}
	var asked int
	svc := NewService(Deps{
		Store: env.Store, Redis: env.Redis, Queue: queue,
		Policy: registerpolicy.New(registerpolicy.Deps{
			Auths:  env.Store.Auth(),
			Config: func() registerpolicy.Snapshot { return policy },
			VerifyTurnstile: func(_ context.Context, _, token, _ string) (bool, error) {
				asked++
				return token == "human", nil
			},
		}),
		Config: func() Snapshot { return Snapshot{VerifyCodeExpire: 300} },
	})
	anonymous := identitytest.Context()

	if _, err := svc.SendEmailCode(anonymous, &dto.SendCodeRequest{Email: "new@example.com", Type: uint8(auth.Register)}); err != nil {
		t.Fatalf("registration code without a token: %v", err)
	}
	if _, err := svc.SendSmsCode(anonymous, &dto.SendSmsCodeRequest{Type: uint8(auth.Register), TelephoneAreaCode: "86", Telephone: "13800138000"}); err != nil {
		t.Fatalf("registration SMS without a token: %v", err)
	}
	if asked != 0 || len(queue.tasks) != 2 {
		t.Fatalf("challenge checks = %d, deliveries = %d, want no challenge and both codes", asked, len(queue.tasks))
	}
}
