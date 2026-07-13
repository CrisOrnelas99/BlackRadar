// Package jwt provides JWT issuance and claim validation for application
// access and refresh tokens.
package jwt

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	accessScope  = "api"
	refreshScope = "auth"

	tokenUseAccess  = "access"
	tokenUseRefresh = "refresh"

	minimumHMACSecretLength = 32
	defaultClockSkew        = 30 * time.Second
)

// Manager issues and validates application JWTs.
type Manager struct {
	secret            []byte
	accessExpiration  time.Duration
	refreshExpiration time.Duration
	issuer            string
	audience          string
	clockSkew         time.Duration
	now               func() time.Time
}

// Claims contains the claims shared by access and refresh tokens.
type Claims struct {
	Username string `json:"username,omitempty"`
	Scope    string `json:"scope"`
	TokenUse string `json:"token_use"`

	jwt.RegisteredClaims
}

// NewManager creates and validates a JWT manager.
func NewManager(
	secret string,
	accessExpiration time.Duration,
	refreshExpiration time.Duration,
	issuer string,
	audience string,
) (*Manager, error) {
	secret = strings.TrimSpace(secret)
	issuer = strings.TrimSpace(issuer)
	audience = strings.TrimSpace(audience)

	if len([]byte(secret)) < minimumHMACSecretLength {
		return nil, fmt.Errorf(
			"JWT secret must contain at least %d bytes",
			minimumHMACSecretLength,
		)
	}
	if accessExpiration <= 0 {
		return nil, errors.New("JWT access expiration must be greater than zero")
	}
	if refreshExpiration <= 0 {
		return nil, errors.New("JWT refresh expiration must be greater than zero")
	}
	if refreshExpiration <= accessExpiration {
		return nil, errors.New("JWT refresh expiration must be greater than access expiration")
	}
	if issuer == "" {
		return nil, errors.New("JWT issuer is required")
	}
	if audience == "" {
		return nil, errors.New("JWT audience is required")
	}

	return &Manager{
		secret:            []byte(secret),
		accessExpiration:  accessExpiration,
		refreshExpiration: refreshExpiration,
		issuer:            issuer,
		audience:          audience,
		clockSkew:         defaultClockSkew,
		now:               time.Now,
	}, nil
}

// GenerateAccessToken creates a signed access token for an authenticated user.
func (manager *Manager) GenerateAccessToken(userID string, username string, tokenID string) (string, error) {
	return manager.generateToken(
		userID,
		username,
		tokenID,
		accessScope,
		tokenUseAccess,
		manager.accessExpiration,
	)
}

// GenerateRefreshToken creates a signed refresh token backed by a server-side session.
func (manager *Manager) GenerateRefreshToken(userID string, username string, tokenID string) (string, error) {
	return manager.generateToken(
		userID,
		username,
		tokenID,
		refreshScope,
		tokenUseRefresh,
		manager.refreshExpiration,
	)
}

// AccessExpiration returns the configured access-token lifetime.
func (manager *Manager) AccessExpiration() time.Duration {
	return manager.accessExpiration
}

// RefreshExpiration returns the configured refresh-token lifetime.
func (manager *Manager) RefreshExpiration() time.Duration {
	return manager.refreshExpiration
}

// ExtractAccessClaims validates an access token and returns its claims.
func (manager *Manager) ExtractAccessClaims(tokenString string) (Claims, error) {
	return manager.extractClaims(tokenString, accessScope, tokenUseAccess)
}

// ExtractRefreshClaims validates a refresh token and returns its claims.
func (manager *Manager) ExtractRefreshClaims(tokenString string) (Claims, error) {
	return manager.extractClaims(tokenString, refreshScope, tokenUseRefresh)
}

// ExtractAccessSubject validates an access token and returns its user ID.
func (manager *Manager) ExtractAccessSubject(tokenString string) (string, error) {
	claims, err := manager.ExtractAccessClaims(tokenString)
	if err != nil {
		return "", err
	}
	return claims.Subject, nil
}

// ExtractRefreshSubject validates a refresh token and returns its user ID.
func (manager *Manager) ExtractRefreshSubject(tokenString string) (string, error) {
	claims, err := manager.ExtractRefreshClaims(tokenString)
	if err != nil {
		return "", err
	}
	return claims.Subject, nil
}

// generateToken creates a signed JWT with a restricted token purpose.
func (manager *Manager) generateToken(
	userID string,
	username string,
	tokenID string,
	scope string,
	tokenUse string,
	expiration time.Duration,
) (string, error) {
	if manager == nil || len(manager.secret) < minimumHMACSecretLength {
		return "", ErrMissingSecret
	}

	userID = strings.TrimSpace(userID)
	username = strings.TrimSpace(username)
	tokenID = strings.TrimSpace(tokenID)

	if userID == "" {
		return "", ErrMissingSubject
	}
	if tokenID == "" {
		return "", ErrInvalidToken
	}
	if expiration <= 0 {
		return "", errors.New("JWT token expiration must be greater than zero")
	}

	now := manager.now().UTC()
	claims := Claims{
		Username: username,
		Scope:    scope,
		TokenUse: tokenUse,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			ID:        tokenID,
			Issuer:    manager.issuer,
			Audience:  jwt.ClaimStrings{manager.audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiration)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(manager.secret)
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}

	return signedToken, nil
}

// extractClaims parses and validates a JWT for the expected purpose.
func (manager *Manager) extractClaims(
	tokenString string,
	expectedScope string,
	expectedTokenUse string,
) (Claims, error) {
	if manager == nil || len(manager.secret) < minimumHMACSecretLength {
		return Claims{}, ErrMissingSecret
	}

	tokenString = strings.TrimSpace(tokenString)
	if tokenString == "" {
		return Claims{}, ErrInvalidToken
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(token *jwt.Token) (any, error) {
			if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
				return nil, ErrUnexpectedSigningMethod
			}
			return manager.secret, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithIssuer(manager.issuer),
		jwt.WithAudience(manager.audience),
		jwt.WithLeeway(manager.clockSkew),
		jwt.WithTimeFunc(manager.now),
	)
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if token == nil || !token.Valid {
		return Claims{}, ErrInvalidToken
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return Claims{}, ErrMissingSubject
	}
	if strings.TrimSpace(claims.ID) == "" {
		return Claims{}, ErrInvalidToken
	}
	if claims.NotBefore == nil {
		return Claims{}, ErrInvalidToken
	}
	if claims.Scope != expectedScope {
		return Claims{}, ErrInvalidScope
	}
	if claims.TokenUse != expectedTokenUse {
		return Claims{}, ErrInvalidTokenUse
	}

	return *claims, nil
}
