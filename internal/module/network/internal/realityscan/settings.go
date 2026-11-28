package realityscan

import (
	"context"
	"errors"

	"github.com/perfect-panel/server/internal/repository"
	"gorm.io/gorm"
)

// SystemSettings adapts the system table to the scanner's settings port.
type SystemSettings struct {
	Repo repository.SystemRepo
}

// Load reads one setting. A missing row is an empty value.
func (s SystemSettings) Load(ctx context.Context, key string) (string, bool, error) {
	if s.Repo == nil {
		return "", false, errors.New("system settings are unavailable")
	}
	row, err := s.Repo.FindOneByKey(ctx, key)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", false, nil
		}
		return "", false, err
	}
	if row == nil || row.Value == "" {
		return "", false, nil
	}
	return row.Value, true, nil
}

// Save writes one setting in the reality scanner category.
func (s SystemSettings) Save(ctx context.Context, key, value string) error {
	if s.Repo == nil {
		return errors.New("system settings are unavailable")
	}
	return s.Repo.UpdateValueByCategoryKey(ctx, category, key, value, "string")
}
