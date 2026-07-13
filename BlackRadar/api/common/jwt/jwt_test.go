package jwt

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testSecret = "0123456789abcdef0123456789abcdef"
	testUserID = "user-1"
)

func TestManagerGenerateAccessTokenAndExtractSubject(t *testing.T) {
	manager := newTestManager(t)

	token, err := manager.GenerateAccessToken(testUserID, "analyst", "session-1")
	if err != nil {
		t.Fatalf("expected token generation to succeed: %v", err)
	}
	if token == "" {
		t.Fatal("expected generated token to be non-empty")
	}

	subject, err := manager.ExtractAccessSubject(token)
	if err != nil {
		t.Fatalf("expected subject extraction to succeed: %v", err)
	}
	if subject != testUserID {
		t.Fatalf("expected subject %q, got %q", testUserID, subject)
	}
	if manager.AccessExpiration() != time.Hour {
		t.Fatalf("expected access expiration %s, got %s", time.Hour, manager.AccessExpiration())
	}
	if manager.RefreshExpiration() != 24*time.Hour {
		t.Fatalf("expected refresh expiration %s, got %s", 24*time.Hour, manager.RefreshExpiration())
	}
}

func TestManagerGenerateAccessTokenIncludesExpectedClaims(t *testing.T) {
	manager := newTestManager(t)

	tokenString, err := manager.GenerateAccessToken(testUserID, "analyst", "session-1")
	if err != nil {
		t.Fatalf("expected token generation to succeed: %v", err)
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(token *jwt.Token) (any, error) {
			return []byte(testSecret), nil
		},
		jwt.WithIssuer("issuer"),
		jwt.WithAudience("audience"),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	if err != nil {
		t.Fatalf("expected generated token to parse: %v", err)
	}
	if !token.Valid {
		t.Fatal("expected generated token to be valid")
	}
	if claims.Subject != testUserID {
		t.Fatalf("expected subject %q, got %q", testUserID, claims.Subject)
	}
	if claims.Username != "analyst" {
		t.Fatalf("expected username analyst, got %q", claims.Username)
	}
	if claims.ID != "session-1" {
		t.Fatalf("expected token id session-1, got %q", claims.ID)
	}
	if claims.Scope != accessScope {
		t.Fatalf("expected scope %q, got %q", accessScope, claims.Scope)
	}
	if claims.TokenUse != tokenUseAccess {
		t.Fatalf("expected token use %q, got %q", tokenUseAccess, claims.TokenUse)
	}
	if claims.ExpiresAt == nil {
		t.Fatal("expected expiration claim to be set")
	}
	if claims.NotBefore == nil {
		t.Fatal("expected not-before claim to be set")
	}
	if claims.IssuedAt == nil {
		t.Fatal("expected issued-at claim to be set")
	}
}

func TestNewManagerValidatesConfiguration(t *testing.T) {
	tests := []struct {
		name              string
		secret            string
		accessExpiration  time.Duration
		refreshExpiration time.Duration
		issuer            string
		audience          string
	}{
		{
			name:              "short secret",
			secret:            "test-secret",
			accessExpiration:  time.Hour,
			refreshExpiration: 24 * time.Hour,
			issuer:            "issuer",
			audience:          "audience",
		},
		{
			name:              "zero access expiration",
			secret:            testSecret,
			accessExpiration:  0,
			refreshExpiration: 24 * time.Hour,
			issuer:            "issuer",
			audience:          "audience",
		},
		{
			name:              "refresh not longer than access",
			secret:            testSecret,
			accessExpiration:  time.Hour,
			refreshExpiration: time.Hour,
			issuer:            "issuer",
			audience:          "audience",
		},
		{
			name:              "missing issuer",
			secret:            testSecret,
			accessExpiration:  time.Hour,
			refreshExpiration: 24 * time.Hour,
			issuer:            "",
			audience:          "audience",
		},
		{
			name:              "missing audience",
			secret:            testSecret,
			accessExpiration:  time.Hour,
			refreshExpiration: 24 * time.Hour,
			issuer:            "issuer",
			audience:          "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewManager(
				tt.secret,
				tt.accessExpiration,
				tt.refreshExpiration,
				tt.issuer,
				tt.audience,
			)
			if err == nil {
				t.Fatalf("expected configuration error, got manager %#v", manager)
			}
		})
	}
}

func TestManagerRequiresTokenID(t *testing.T) {
	manager := newTestManager(t)

	token, err := manager.GenerateAccessToken(testUserID, "analyst", "")
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken from GenerateAccessToken, got token=%q err=%v", token, err)
	}
}

func TestManagerRequiresSubject(t *testing.T) {
	manager := newTestManager(t)

	token, err := manager.GenerateAccessToken("", "analyst", "session-1")
	if !errors.Is(err, ErrMissingSubject) {
		t.Fatalf("expected ErrMissingSubject from GenerateAccessToken, got token=%q err=%v", token, err)
	}
}

func TestManagerRejectsInvalidTokens(t *testing.T) {
	manager := newTestManager(t)

	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "malformed token",
			token: "not-a-token",
		},
		{
			name: "wrong signing secret",
			token: signToken(t, "0123456789abcdef0123456789abcdee", Claims{
				Scope:            accessScope,
				TokenUse:         tokenUseAccess,
				RegisteredClaims: validRegisteredClaims(testUserID, "session-1"),
			}),
		},
		{
			name: "expired token",
			token: signToken(t, testSecret, Claims{
				Scope:    accessScope,
				TokenUse: tokenUseAccess,
				RegisteredClaims: jwt.RegisteredClaims{
					Subject:   testUserID,
					ID:        "session-1",
					Issuer:    "issuer",
					Audience:  jwt.ClaimStrings{"audience"},
					IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
					NotBefore: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
				},
			}),
		},
		{
			name: "wrong issuer",
			token: signToken(t, testSecret, Claims{
				Scope:    accessScope,
				TokenUse: tokenUseAccess,
				RegisteredClaims: jwt.RegisteredClaims{
					Subject:   testUserID,
					ID:        "session-1",
					Issuer:    "other-issuer",
					Audience:  jwt.ClaimStrings{"audience"},
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					NotBefore: jwt.NewNumericDate(time.Now()),
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				},
			}),
		},
		{
			name: "wrong audience",
			token: signToken(t, testSecret, Claims{
				Scope:    accessScope,
				TokenUse: tokenUseAccess,
				RegisteredClaims: jwt.RegisteredClaims{
					Subject:   testUserID,
					ID:        "session-1",
					Issuer:    "issuer",
					Audience:  jwt.ClaimStrings{"other-audience"},
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					NotBefore: jwt.NewNumericDate(time.Now()),
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				},
			}),
		},
		{
			name: "missing expiration",
			token: signToken(t, testSecret, Claims{
				Scope:    accessScope,
				TokenUse: tokenUseAccess,
				RegisteredClaims: jwt.RegisteredClaims{
					Subject:   testUserID,
					ID:        "session-1",
					Issuer:    "issuer",
					Audience:  jwt.ClaimStrings{"audience"},
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					NotBefore: jwt.NewNumericDate(time.Now()),
				},
			}),
		},
		{
			name: "missing not before",
			token: signToken(t, testSecret, Claims{
				Scope:    accessScope,
				TokenUse: tokenUseAccess,
				RegisteredClaims: jwt.RegisteredClaims{
					Subject:   testUserID,
					ID:        "session-1",
					Issuer:    "issuer",
					Audience:  jwt.ClaimStrings{"audience"},
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				},
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subject, err := manager.ExtractAccessSubject(tt.token)
			if !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("expected ErrInvalidToken, got subject=%q err=%v", subject, err)
			}
		})
	}
}

func TestManagerRejectsInvalidApplicationClaims(t *testing.T) {
	manager := newTestManager(t)

	tests := []struct {
		name      string
		claims    Claims
		expectErr error
	}{
		{
			name: "missing subject",
			claims: Claims{
				Scope:    accessScope,
				TokenUse: tokenUseAccess,
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    "issuer",
					ID:        "session-1",
					Audience:  jwt.ClaimStrings{"audience"},
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					NotBefore: jwt.NewNumericDate(time.Now()),
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				},
			},
			expectErr: ErrMissingSubject,
		},
		{
			name: "missing token id",
			claims: Claims{
				Scope:            accessScope,
				TokenUse:         tokenUseAccess,
				RegisteredClaims: validRegisteredClaims(testUserID, ""),
			},
			expectErr: ErrInvalidToken,
		},
		{
			name: "invalid scope",
			claims: Claims{
				Scope:            "admin",
				TokenUse:         tokenUseAccess,
				RegisteredClaims: validRegisteredClaims(testUserID, "session-1"),
			},
			expectErr: ErrInvalidScope,
		},
		{
			name: "invalid token use",
			claims: Claims{
				Scope:            accessScope,
				TokenUse:         tokenUseRefresh,
				RegisteredClaims: validRegisteredClaims(testUserID, "session-1"),
			},
			expectErr: ErrInvalidTokenUse,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := signToken(t, testSecret, tt.claims)

			subject, err := manager.ExtractAccessSubject(token)
			if !errors.Is(err, tt.expectErr) {
				t.Fatalf("expected %v, got subject=%q err=%v", tt.expectErr, subject, err)
			}
		})
	}
}

func TestManagerGeneratesAndValidatesRefreshTokens(t *testing.T) {
	manager := newTestManager(t)

	token, err := manager.GenerateRefreshToken(testUserID, "analyst", "refresh-session-1")
	if err != nil {
		t.Fatalf("expected refresh token generation to succeed: %v", err)
	}

	claims, err := manager.ExtractRefreshClaims(token)
	if err != nil {
		t.Fatalf("expected refresh token extraction to succeed: %v", err)
	}
	if claims.Subject != testUserID {
		t.Fatalf("expected refresh subject %q, got %q", testUserID, claims.Subject)
	}
	if claims.Username != "analyst" {
		t.Fatalf("expected refresh username analyst, got %q", claims.Username)
	}
	if claims.ID != "refresh-session-1" {
		t.Fatalf("expected refresh token id refresh-session-1, got %q", claims.ID)
	}
}

func TestInvalidTokenWrapsParserDetailsWithoutExposingJwtErrorMatching(t *testing.T) {
	manager := newTestManager(t)

	_, err := manager.ExtractAccessSubject("not-a-token")
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected invalid token sentinel, got %v", err)
	}
	if !strings.Contains(err.Error(), ErrInvalidToken.Error()) {
		t.Fatalf("expected wrapped error to include sentinel message, got %v", err)
	}
}

func newTestManager(t *testing.T) *Manager {
	t.Helper()

	manager, err := NewManager(testSecret, time.Hour, 24*time.Hour, "issuer", "audience")
	if err != nil {
		t.Fatalf("expected test manager configuration to be valid: %v", err)
	}

	return manager
}

func signToken(t *testing.T, secret string, claims Claims) string {
	t.Helper()

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	return token
}

func validRegisteredClaims(subject string, id string) jwt.RegisteredClaims {
	return jwt.RegisteredClaims{
		Subject:   subject,
		ID:        id,
		Issuer:    "issuer",
		Audience:  jwt.ClaimStrings{"audience"},
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
}
