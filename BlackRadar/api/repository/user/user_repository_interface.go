package repository

import (
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
)

type UserRepositoryInterface interface {
	ExistsByUsername(ec *appcontext.GinContext, username string) (bool, error)
	ExistsByEmail(ec *appcontext.GinContext, email string) (bool, error)
	Save(ec *appcontext.GinContext, user model.User) (model.User, error)
	FindByUsername(ec *appcontext.GinContext, username string) (model.User, error)
	FindByID(ec *appcontext.GinContext, id string) (model.User, error)
	FindByEmail(ec *appcontext.GinContext, email string) (model.User, error)
}

type RefreshSessionRepositoryInterface interface {
	Save(ec *appcontext.GinContext, session model.RefreshSession) error
	FindActiveByTokenIDForUser(ec *appcontext.GinContext, tokenID string, userID string) (model.RefreshSession, error)
	RevokeByTokenIDForUser(ec *appcontext.GinContext, tokenID string, userID string) error
}
