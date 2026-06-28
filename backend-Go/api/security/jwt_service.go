// Package security provides JWT management and token claim validation helpers.
package security

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTManager issues and validates backend JWT access tokens.
type JWTManager struct {
	secret            []byte
	expiration        time.Duration
	refreshExpiration time.Duration
	issuer            string
	audience          string
}

// AccessClaims holds the JWT claims used for backend access tokens.
type AccessClaims struct {
	Scope    string `json:"scope"`
	TokenUse string `json:"tokenUse"`
	jwt.RegisteredClaims
}

const (
	accessScope     = "api"
	refreshScope    = "auth"
	tokenUseAccess  = "access"
	tokenUseRefresh = "refresh"
)

// NewJWTManager creates a JWT manager with the configured signing settings.
func NewJWTManager(secret string, expiration time.Duration, refreshExpiration time.Duration, issuer string, audience string) *JWTManager {
	return &JWTManager{secret: []byte(secret), expiration: expiration, refreshExpiration: refreshExpiration, issuer: issuer, audience: audience}
}

// GenerateToken creates a signed access token for the given username and session ID.
func (s *JWTManager) GenerateToken(username string, tokenID string) (string, error) {
	return s.generateToken(username, tokenID, accessScope, tokenUseAccess, s.expiration)
}

// GenerateRefreshToken creates a signed refresh token for the given username.
func (s *JWTManager) GenerateRefreshToken(username string, tokenID string) (string, error) {
	return s.generateToken(username, tokenID, refreshScope, tokenUseRefresh, s.refreshExpiration)
}

// RefreshExpiration returns the configured refresh token lifetime.
func (s *JWTManager) RefreshExpiration() time.Duration {
	return s.refreshExpiration
}

// ExtractUsername validates an access token and returns the subject username.
func (s *JWTManager) ExtractUsername(tokenString string) (string, error) {
	claims, err := s.ExtractAccessClaims(tokenString)
	if err != nil {
		return "", err
	}
	return claims.Subject, nil
}

// ExtractAccessClaims validates an access token and returns its claims.
func (s *JWTManager) ExtractAccessClaims(tokenString string) (AccessClaims, error) {
	return s.extractClaims(tokenString, accessScope, tokenUseAccess)
}

// ExtractRefreshUsername validates a refresh token and returns the subject username.
func (s *JWTManager) ExtractRefreshUsername(tokenString string) (string, error) {
	claims, err := s.ExtractRefreshClaims(tokenString)
	if err != nil {
		return "", err
	}
	return claims.Subject, nil
}

// ExtractRefreshClaims validates a refresh token and returns its claims.
func (s *JWTManager) ExtractRefreshClaims(tokenString string) (AccessClaims, error) {
	return s.extractClaims(tokenString, refreshScope, tokenUseRefresh)
}

func (s *JWTManager) generateToken(username string, tokenID string, scope string, tokenUse string, expiration time.Duration) (string, error) {
	if len(s.secret) == 0 {
		return "", ErrMissingSecret
	}

	now := time.Now()
	claims := AccessClaims{
		Scope:    scope,
		TokenUse: tokenUse,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
			ID:        tokenID,
			Issuer:    s.issuer,
			Audience:  jwt.ClaimStrings{s.audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiration)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.secret)
}

func (s *JWTManager) extractClaims(tokenString string, scope string, tokenUse string) (AccessClaims, error) {
	if len(s.secret) == 0 {
		return AccessClaims{}, ErrMissingSecret
	}

	claims := &AccessClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, ErrUnexpectedSigningMethod
		}
		return s.secret, nil
	}, jwt.WithExpirationRequired(), jwt.WithIssuer(s.issuer), jwt.WithAudience(s.audience), jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil || !token.Valid {
		return AccessClaims{}, ErrInvalidToken
	}
	if claims.Subject == "" {
		return AccessClaims{}, ErrMissingSubject
	}
	if claims.Scope != scope {
		return AccessClaims{}, ErrInvalidScope
	}
	if claims.TokenUse != tokenUse {
		return AccessClaims{}, ErrInvalidTokenUse
	}
	return *claims, nil
}
