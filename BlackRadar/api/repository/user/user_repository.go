// Package repository provides user persistence operations.
package repository

import (
	"errors"
	"fmt"
	"strings"
	"time"

	commonid "blackradar/api/common/id"
	"blackradar/api/common/pagination"
	"blackradar/api/model"
	platformdb "blackradar/api/platform/db"
	appcontext "blackradar/api/platform/requestcontext"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// UserRepository persists user records.
type UserRepository struct {
	db *gorm.DB
}

// NewUserRepository creates a user repository backed by the supplied database.
func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

// RefreshSessionRepository persists refresh token sessions.
type RefreshSessionRepository struct {
	db *gorm.DB
}

// NewRefreshSessionRepository creates a refresh session repository backed by the supplied database.
func NewRefreshSessionRepository(db *gorm.DB) *RefreshSessionRepository {
	return &RefreshSessionRepository{db: db}
}

// ListUsers returns active and deactivated user accounts in stable creation order.
func (r *UserRepository) ListUsers(ec *appcontext.GinContext, query model.UserListQuery) (pagination.Page[model.User], error) {
	if err := RequirePermission(ec, r.dbForContext(ec), model.PermissionManageUsers); err != nil {
		return pagination.Page[model.User]{}, err
	}
	request := query.Pagination
	result := pagination.Page[model.User]{Page: request.Page, PageSize: request.PageSize, Items: []model.User{}}
	database := r.dbForContext(ec).WithContext(ec.RequestContext()).Model(&model.User{})
	if search := strings.TrimSpace(query.Search); search != "" {
		database = database.Where("(full_name ILIKE ? OR username ILIKE ? OR email ILIKE ?)", userSearchPattern(search), userSearchPattern(search), userSearchPattern(search))
	}
	if query.Role != "" {
		database = database.Where("role = ?", query.Role)
	}
	if query.AccountStatus != "" {
		database = database.Where("account_status = ?", query.AccountStatus)
	}
	if err := database.Count(&result.TotalCount).Error; err != nil {
		return pagination.Page[model.User]{}, fmt.Errorf("%w: count users: %w", ErrPersistenceFailure, err)
	}
	if result.TotalCount == 0 {
		return result, nil
	}
	if err := database.Select("id, full_name, username, email, role, account_status, created_at, updated_at").Order(userListOrder(query)).Order("id ASC").Offset((request.Page - 1) * request.PageSize).Limit(request.PageSize).Find(&result.Items).Error; err != nil {
		return pagination.Page[model.User]{}, fmt.Errorf("%w: read user page: %w", ErrPersistenceFailure, err)
	}
	return result, nil
}

func userSearchPattern(value string) string {
	escaped := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(strings.ToLower(value))
	return "%" + escaped + "%"
}

func userListOrder(query model.UserListQuery) string {
	column := "LOWER(full_name)"
	switch query.SortField {
	case model.UserSortUsername:
		column = "LOWER(username)"
	case model.UserSortEmail:
		column = "LOWER(email)"
	case model.UserSortRole:
		column = "LOWER(role)"
	case model.UserSortStatus:
		column = "LOWER(account_status)"
	}
	if query.SortDirection == model.UserSortDescending {
		return column + " DESC"
	}
	return column + " ASC"
}

// ExistsByUsername reports whether a username already exists.
func (r *UserRepository) ExistsByUsername(ec *appcontext.GinContext, username string) (bool, error) {
	var count int64
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).Model(&model.User{}).Where("username = ?", strings.TrimSpace(username)).Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("%w: check username uniqueness: %w", ErrPersistenceFailure, err)
	}
	return count > 0, nil
}

// ExistsByUsernameExceptID reports whether another active user uses username.
func (r *UserRepository) ExistsByUsernameExceptID(ec *appcontext.GinContext, username string, userID string) (bool, error) {
	var count int64
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).Model(&model.User{}).
		Where("username = ? AND id <> ?", strings.TrimSpace(username), strings.TrimSpace(userID)).
		Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("%w: check username uniqueness: %w", ErrPersistenceFailure, err)
	}
	return count > 0, nil
}

// ExistsByEmail reports whether an email address already exists.
func (r *UserRepository) ExistsByEmail(ec *appcontext.GinContext, email string) (bool, error) {
	var count int64
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).Model(&model.User{}).Where("email = ?", strings.ToLower(strings.TrimSpace(email))).Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("%w: check email uniqueness: %w", ErrPersistenceFailure, err)
	}
	return count > 0, nil
}

// ExistsByEmailExceptID reports whether another active user uses email.
func (r *UserRepository) ExistsByEmailExceptID(ec *appcontext.GinContext, email string, userID string) (bool, error) {
	var count int64
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).Model(&model.User{}).
		Where("email = ? AND id <> ?", strings.ToLower(strings.TrimSpace(email)), strings.TrimSpace(userID)).
		Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("%w: check email uniqueness: %w", ErrPersistenceFailure, err)
	}
	return count > 0, nil
}

// CreateUser creates a new user record.
func (r *UserRepository) CreateUser(ec *appcontext.GinContext, user model.User) (model.User, error) {
	if user.Username == "" || user.Email == "" || user.PasswordHash == "" {
		return model.User{}, ErrNotNullViolation
	}
	user.OrganizationID = model.SingleOrganizationID

	for attempt := 0; attempt < 3; attempt++ {
		identifier, err := commonid.New()
		if err != nil {
			return model.User{}, fmt.Errorf("%w: generate user id: %w", ErrPersistenceFailure, err)
		}
		user.ID = identifier

		err = r.dbForContext(ec).WithContext(ec.RequestContext()).Create(&user).Error
		if err == nil {
			return user, nil
		}

		databaseErr := platformdb.TranslateDatabaseError(err)
		if errors.Is(databaseErr, platformdb.ErrUniqueViolation) && platformdb.IsPrimaryKeyViolation(err) {
			continue
		}
		if errors.Is(databaseErr, platformdb.ErrUniqueViolation) {
			return model.User{}, fmt.Errorf("%w: %w", ErrUniqueViolation, databaseErr)
		}
		if errors.Is(databaseErr, platformdb.ErrForeignKeyViolation) {
			return model.User{}, fmt.Errorf("%w: %w", ErrForeignKeyViolation, databaseErr)
		}
		if errors.Is(databaseErr, platformdb.ErrCheckConstraintViolation) {
			return model.User{}, fmt.Errorf("%w: %w", ErrCheckConstraintViolation, databaseErr)
		}
		return model.User{}, fmt.Errorf("%w: create user: %w", ErrPersistenceFailure, databaseErr)
	}

	return model.User{}, fmt.Errorf("%w: exhausted random id retries", ErrPrimaryKeyViolation)
}

// UpdateRole changes a managed user's role.
func (r *UserRepository) UpdateRole(ec *appcontext.GinContext, userID string, role string, updatedByID string) (model.User, error) {
	if err := RequirePermission(ec, r.dbForContext(ec), model.PermissionManageUsers); err != nil {
		return model.User{}, err
	}
	result := r.dbForContext(ec).WithContext(ec.RequestContext()).Model(&model.User{}).Where("id = ?", strings.TrimSpace(userID)).Updates(map[string]any{"role": role, "updated_by_id": updatedByID})
	if result.Error != nil {
		return model.User{}, fmt.Errorf("%w: update user role: %w", ErrPersistenceFailure, result.Error)
	}
	if result.RowsAffected == 0 {
		return model.User{}, ErrRecordNotFound
	}
	return r.FindByIDForManagement(ec, userID)
}

// UpdateAccountStatus changes a managed user's account status.
func (r *UserRepository) UpdateAccountStatus(ec *appcontext.GinContext, userID string, status string, updatedByID string) (model.User, error) {
	if err := RequirePermission(ec, r.dbForContext(ec), model.PermissionManageUsers); err != nil {
		return model.User{}, err
	}
	result := r.dbForContext(ec).WithContext(ec.RequestContext()).Model(&model.User{}).Where("id = ?", strings.TrimSpace(userID)).Updates(map[string]any{"account_status": status, "updated_by_id": updatedByID})
	if result.Error != nil {
		return model.User{}, fmt.Errorf("%w: update account status: %w", ErrPersistenceFailure, result.Error)
	}
	if result.RowsAffected == 0 {
		return model.User{}, ErrRecordNotFound
	}
	return r.FindByIDForManagement(ec, userID)
}

func (r *UserRepository) CountActiveAdmins(ec *appcontext.GinContext) (int64, error) {
	var admins []struct{ ID string }
	if err := r.dbForContext(ec).WithContext(ec.RequestContext()).Model(&model.User{}).Select("id").Where("role = ? AND account_status = ?", model.RoleAdmin, model.AccountStatusActive).Clauses(clause.Locking{Strength: "UPDATE"}).Find(&admins).Error; err != nil {
		return 0, fmt.Errorf("%w: count active admins: %w", ErrPersistenceFailure, err)
	}
	return int64(len(admins)), nil
}

// UpdateProfile updates the mutable profile fields for one active user.
func (r *UserRepository) UpdateProfile(ec *appcontext.GinContext, userID string, user model.User) (model.User, error) {
	if strings.TrimSpace(userID) == "" || user.FullName == "" || user.Username == "" || user.Email == "" {
		return model.User{}, ErrNotNullViolation
	}

	result := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Model(&model.User{}).
		Where("id = ?", strings.TrimSpace(userID)).
		Updates(map[string]any{
			"full_name": user.FullName,
			"username":  user.Username,
			"email":     user.Email,
		})
	if result.Error != nil {
		databaseErr := platformdb.TranslateDatabaseError(result.Error)
		if errors.Is(databaseErr, platformdb.ErrUniqueViolation) {
			return model.User{}, fmt.Errorf("%w: %w", ErrUniqueViolation, databaseErr)
		}
		return model.User{}, fmt.Errorf("%w: update profile: %w", ErrPersistenceFailure, databaseErr)
	}
	if result.RowsAffected == 0 {
		return model.User{}, ErrRecordNotFound
	}

	return r.FindByID(ec, userID)
}

// FindByUsername returns a user that matches the supplied username.
func (r *UserRepository) FindByUsername(ec *appcontext.GinContext, username string) (model.User, error) {
	var user model.User
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).Where("username = ? AND account_status = ?", strings.TrimSpace(username), model.AccountStatusActive).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.User{}, ErrRecordNotFound
	}
	if err != nil {
		return model.User{}, fmt.Errorf("%w: read user by username: %w", ErrPersistenceFailure, err)
	}
	return user, nil
}

// FindByID returns a user that matches the supplied immutable identifier.
func (r *UserRepository) FindByID(ec *appcontext.GinContext, id string) (model.User, error) {
	var user model.User
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).Where("id = ? AND account_status = ?", strings.TrimSpace(id), model.AccountStatusActive).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.User{}, ErrRecordNotFound
	}
	if err != nil {
		return model.User{}, fmt.Errorf("%w: read user by id: %w", ErrPersistenceFailure, err)
	}
	return user, nil
}

// FindByIDForManagement returns an active or deactivated account.
func (r *UserRepository) FindByIDForManagement(ec *appcontext.GinContext, id string) (model.User, error) {
	var user model.User
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).Where("id = ?", strings.TrimSpace(id)).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.User{}, ErrRecordNotFound
	}
	if err != nil {
		return model.User{}, fmt.Errorf("%w: read managed user by id: %w", ErrPersistenceFailure, err)
	}
	return user, nil
}

// FindByEmail returns a user that matches the supplied email.
func (r *UserRepository) FindByEmail(ec *appcontext.GinContext, email string) (model.User, error) {
	var user model.User
	err := r.dbForContext(ec).WithContext(ec.RequestContext()).Where("email = ? AND account_status = ?", strings.ToLower(strings.TrimSpace(email)), model.AccountStatusActive).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.User{}, ErrRecordNotFound
	}
	if err != nil {
		return model.User{}, fmt.Errorf("%w: read user by email: %w", ErrPersistenceFailure, err)
	}
	return user, nil
}

// UpdateLoginBackoff stores account-specific login failure state.
func (r *UserRepository) UpdateLoginBackoff(ec *appcontext.GinContext, userID string, failedCount int, lastFailedAt, lockedUntil *time.Time) error {
	if strings.TrimSpace(userID) == "" || failedCount < 0 {
		return ErrNotNullViolation
	}

	result := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Model(&model.User{}).
		Where("id = ?", userID).
		Updates(map[string]any{
			"failed_login_count":   failedCount,
			"last_failed_login_at": lastFailedAt,
			"locked_until":         lockedUntil,
		})
	if result.Error != nil {
		return fmt.Errorf("%w: update login backoff: %w", ErrPersistenceFailure, result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrRecordNotFound
	}
	return nil
}

// CreateRefreshSession creates a new refresh session.
func (r *RefreshSessionRepository) CreateRefreshSession(ec *appcontext.GinContext, session model.RefreshSession) error {
	if session.TokenID == "" || session.UserID == "" || session.DeviceName == "" || session.ExpiresAt.IsZero() {
		return ErrNotNullViolation
	}

	err := r.dbForContext(ec).WithContext(ec.RequestContext()).Create(&session).Error
	if err != nil {
		databaseErr := platformdb.TranslateDatabaseError(err)
		if errors.Is(databaseErr, platformdb.ErrUniqueViolation) {
			return fmt.Errorf("%w: %w", ErrUniqueViolation, databaseErr)
		}
		if errors.Is(databaseErr, platformdb.ErrForeignKeyViolation) {
			return fmt.Errorf("%w: %w", ErrForeignKeyViolation, databaseErr)
		}
		if errors.Is(databaseErr, platformdb.ErrCheckConstraintViolation) {
			return fmt.Errorf("%w: %w", ErrCheckConstraintViolation, databaseErr)
		}
		return fmt.Errorf("%w: create refresh session: %w", ErrPersistenceFailure, databaseErr)
	}
	return nil
}

// FindActiveByTokenIDForUser returns an unrevoked refresh session for a user.
func (r *RefreshSessionRepository) FindActiveByTokenIDForUser(ec *appcontext.GinContext, tokenID string, userID string) (model.RefreshSession, error) {
	var session model.RefreshSession
	err := activeRefreshSessionQuery(
		r.dbForContext(ec).WithContext(ec.RequestContext()),
		tokenID,
		userID,
		time.Now().UTC(),
	).
		First(&session).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.RefreshSession{}, ErrRecordNotFound
	}
	if err != nil {
		return model.RefreshSession{}, fmt.Errorf("%w: read refresh session: %w", ErrPersistenceFailure, err)
	}
	return session, nil
}

// RevokeByTokenIDForUser marks the specified refresh session revoked.
func (r *RefreshSessionRepository) RevokeByTokenIDForUser(ec *appcontext.GinContext, tokenID string, userID string) error {
	now := time.Now().UTC()
	result := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Model(&model.RefreshSession{}).
		Where("token_id = ? AND user_id = ? AND revoked_at IS NULL", tokenID, userID).
		Update("revoked_at", &now)
	if result.Error != nil {
		err := result.Error
		return fmt.Errorf("%w: revoke refresh session: %w", ErrPersistenceFailure, err)
	}
	if result.RowsAffected == 0 {
		return ErrRecordNotFound
	}
	return nil
}

// RevokeActiveSessionsForUser marks every active refresh session for a user revoked.
func (r *RefreshSessionRepository) RevokeActiveSessionsForUser(ec *appcontext.GinContext, userID string) error {
	now := time.Now().UTC()
	result := r.dbForContext(ec).WithContext(ec.RequestContext()).
		Model(&model.RefreshSession{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Update("revoked_at", &now)
	if result.Error != nil {
		return fmt.Errorf("%w: revoke refresh sessions: %w", ErrPersistenceFailure, result.Error)
	}
	return nil
}
