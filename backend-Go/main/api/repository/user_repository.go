package repository

import (
	"errors"
	"fmt"

	"gorm.io/gorm"

	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/model"
	"secureops/backend-go/api/utils"
)

type UserRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) database(ec *appcontext.GinContext) *gorm.DB {
	if ec != nil && ec.Database() != nil {
		return ec.Database()
	}
	return r.db
}

func (r *UserRepository) ExistsByUsername(ec *appcontext.GinContext, username string) (bool, error) {
	var count int64
	err := r.database(ec).WithContext(ec.RequestContext()).Model(&model.User{}).Where("username = ?", username).Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrReadFailed, err)
	}
	return count > 0, err
}

func (r *UserRepository) ExistsByEmail(ec *appcontext.GinContext, email string) (bool, error) {
	var count int64
	err := r.database(ec).WithContext(ec.RequestContext()).Model(&model.User{}).Where("email = ?", email).Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrReadFailed, err)
	}
	return count > 0, err
}

func (r *UserRepository) Save(ec *appcontext.GinContext, user model.User) error {
	if user.Username == "" || user.Email == "" || user.PasswordHash == "" {
		return ErrInvalidData
	}

	err := r.database(ec).WithContext(ec.RequestContext()).Create(&user).Error
	if err != nil {
		if utils.IsForeignKeyViolation(err) {
			return fmt.Errorf("%w: %w", ErrInvalidReference, err)
		}
		if utils.IsCheckConstraintViolation(err) {
			return fmt.Errorf("%w: %w", ErrInvalidData, err)
		}
		return fmt.Errorf("%w: %w", ErrCreateFailed, err)
	}
	return nil
}

func (r *UserRepository) FindByUsernameOrEmail(ec *appcontext.GinContext, userOrEmail string) (model.User, error) {
	var user model.User
	err := r.database(ec).WithContext(ec.RequestContext()).
		Where("username = ? OR email = ?", userOrEmail, userOrEmail).
		First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.User{}, gorm.ErrRecordNotFound
	}
	if err != nil {
		return model.User{}, fmt.Errorf("%w: %w", ErrReadFailed, err)
	}
	return user, err
}

func (r *UserRepository) FindByUsername(ec *appcontext.GinContext, username string) (model.User, error) {
	var user model.User
	err := r.database(ec).WithContext(ec.RequestContext()).Where("username = ?", username).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.User{}, gorm.ErrRecordNotFound
	}
	if err != nil {
		return model.User{}, fmt.Errorf("%w: %w", ErrReadFailed, err)
	}
	return user, nil
}
