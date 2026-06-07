package repository

import (
	"fmt"

	"gorm.io/gorm"

	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/model"
)

type WafEventRepository struct {
	db *gorm.DB
}

func NewWafEventRepository(db *gorm.DB) *WafEventRepository {
	return &WafEventRepository{db: db}
}

func GetWafEventRepoFromEchoContext(ec *appcontext.EchoContext) *WafEventRepository {
	if ec == nil {
		return &WafEventRepository{}
	}

	if value, exists := ec.Get(appcontext.WafEventRepoKey); exists {
		if repo, ok := value.(*WafEventRepository); ok {
			return repo
		}
	}

	repo := &WafEventRepository{}
	ec.Set(appcontext.WafEventRepoKey, repo)
	return repo
}

func (r *WafEventRepository) database(ec *appcontext.EchoContext) *gorm.DB {
	if ec != nil && ec.Database() != nil {
		return ec.Database()
	}
	return r.db
}

func (r *WafEventRepository) Save(ec *appcontext.EchoContext, event model.WafEvent) error {
	if event.Method == "" || event.Path == "" || event.Reason == "" {
		return ErrInvalidData
	}

	err := r.database(ec).WithContext(ec.RequestContext()).Create(&event).Error
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCreateFailed, err)
	}
	return nil
}
