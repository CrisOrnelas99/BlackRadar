package repository

import (
	"errors"
	"fmt"

	"gorm.io/gorm"

	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/model"
	"secureops/backend-go/api/shared"
)

type UserRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

func GetUserRepoFromEchoContext(ec *appcontext.EchoContext) *UserRepository {
	if ec == nil {
		return &UserRepository{}
	}

	if value, exists := ec.Get(appcontext.UserRepoKey); exists {
		if repo, ok := value.(*UserRepository); ok {
			return repo
		}
	}

	repo := &UserRepository{}
	ec.Set(appcontext.UserRepoKey, repo)
	return repo
}

func (r *UserRepository) database(ec *appcontext.EchoContext) *gorm.DB {
	if ec != nil && ec.Database() != nil {
		return ec.Database()
	}
	return r.db
}

func (r *UserRepository) ExistsByUsername(ec *appcontext.EchoContext, username string) (bool, error) {
	var count int64
	err := r.database(ec).WithContext(ec.RequestContext()).Model(&model.User{}).Where("username = ?", username).Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrReadFailed, err)
	}
	return count > 0, err
}

func (r *UserRepository) ExistsByEmail(ec *appcontext.EchoContext, email string) (bool, error) {
	var count int64
	err := r.database(ec).WithContext(ec.RequestContext()).Model(&model.User{}).Where("email = ?", email).Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrReadFailed, err)
	}
	return count > 0, err
}

func (r *UserRepository) Save(ec *appcontext.EchoContext, user model.User) error {
	if user.Username == "" || user.Email == "" || user.PasswordHash == "" {
		return ErrInvalidData
	}

	err := r.database(ec).WithContext(ec.RequestContext()).Create(&user).Error
	if err != nil {
		if shared.IsForeignKeyViolation(err) {
			return fmt.Errorf("%w: %w", ErrInvalidReference, err)
		}
		if shared.IsCheckConstraintViolation(err) {
			return fmt.Errorf("%w: %w", ErrInvalidData, err)
		}
		return fmt.Errorf("%w: %w", ErrCreateFailed, err)
	}
	return nil
}

func (r *UserRepository) FindByUsernameOrEmail(ec *appcontext.EchoContext, userOrEmail string) (model.User, error) {
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
