package service

import (
	"blackradar/api/model"
	appcontext "blackradar/api/platform/requestcontext"
)

type UserService interface {
	Register(ec *appcontext.GinContext, request RegisterInput) (model.User, error)
	Login(ec *appcontext.GinContext, request LoginInput) (LoginResult, error)
	Refresh(ec *appcontext.GinContext, request RefreshInput) (LoginResult, error)
	Logout(ec *appcontext.GinContext, request RefreshInput) error
}
