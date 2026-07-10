package security

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"blackradar/api/model"
)

func TestJWTManagerGenerateTokenAndExtractUsername(t *testing.T) {
	manager := NewJWTManager("test-secret", time.Hour, time.Hour*24, "issuer", "audience")

	token, err := manager.GenerateToken("analyst", "session-1")
	if err != nil {
		t.Fatalf("expected token generation to succeed: %v", err)
	}
	if token == "" {
		t.Fatal("expected generated token to be non-empty")
	}

	username, err := manager.ExtractUsername(token)
	if err != nil {
		t.Fatalf("expected username extraction to succeed: %v", err)
	}
	if username != "analyst" {
		t.Fatalf("expected username analyst, got %q", username)
	}
	if manager.AccessExpiration() != time.Hour {
		t.Fatalf("expected access expiration %s, got %s", time.Hour, manager.AccessExpiration())
	}
	if manager.RefreshExpiration() != 24*time.Hour {
		t.Fatalf("expected refresh expiration %s, got %s", 24*time.Hour, manager.RefreshExpiration())
	}
}

func TestJWTManagerGenerateTokenIncludesExpectedClaims(t *testing.T) {
	manager := NewJWTManager("test-secret", time.Hour, time.Hour*24, "issuer", "audience")

	tokenString, err := manager.GenerateToken("analyst", "session-1")
	if err != nil {
		t.Fatalf("expected token generation to succeed: %v", err)
	}

	claims := &AccessClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		return []byte("test-secret"), nil
	}, jwt.WithIssuer("issuer"), jwt.WithAudience("audience"), jwt.WithExpirationRequired())
	if err != nil {
		t.Fatalf("expected generated token to parse: %v", err)
	}
	if !token.Valid {
		t.Fatal("expected generated token to be valid")
	}
	if claims.Subject != "analyst" {
		t.Fatalf("expected subject analyst, got %q", claims.Subject)
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
}

func TestJWTManagerRequiresSecret(t *testing.T) {
	manager := NewJWTManager("", time.Hour, time.Hour*24, "issuer", "audience")

	token, err := manager.GenerateToken("analyst", "session-1")
	if !errors.Is(err, ErrMissingSecret) {
		t.Fatalf("expected ErrMissingSecret from GenerateToken, got token=%q err=%v", token, err)
	}

	username, err := manager.ExtractUsername("token")
	if !errors.Is(err, ErrMissingSecret) {
		t.Fatalf("expected ErrMissingSecret from ExtractUsername, got username=%q err=%v", username, err)
	}
}

func TestJWTManagerRejectsInvalidTokens(t *testing.T) {
	manager := NewJWTManager("test-secret", time.Hour, time.Hour*24, "issuer", "audience")

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
			token: signToken(t, "wrong-secret", AccessClaims{
				Scope:            accessScope,
				TokenUse:         tokenUseAccess,
				RegisteredClaims: validRegisteredClaims("analyst", "session-1"),
			}),
		},
		{
			name: "expired token",
			token: signToken(t, "test-secret", AccessClaims{
				Scope:    accessScope,
				TokenUse: tokenUseAccess,
				RegisteredClaims: jwt.RegisteredClaims{
					Subject:   "analyst",
					ID:        "session-1",
					Issuer:    "issuer",
					Audience:  jwt.ClaimStrings{"audience"},
					IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
				},
			}),
		},
		{
			name: "wrong issuer",
			token: signToken(t, "test-secret", AccessClaims{
				Scope:    accessScope,
				TokenUse: tokenUseAccess,
				RegisteredClaims: jwt.RegisteredClaims{
					Subject:   "analyst",
					ID:        "session-1",
					Issuer:    "other-issuer",
					Audience:  jwt.ClaimStrings{"audience"},
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				},
			}),
		},
		{
			name: "wrong audience",
			token: signToken(t, "test-secret", AccessClaims{
				Scope:    accessScope,
				TokenUse: tokenUseAccess,
				RegisteredClaims: jwt.RegisteredClaims{
					Subject:   "analyst",
					ID:        "session-1",
					Issuer:    "issuer",
					Audience:  jwt.ClaimStrings{"other-audience"},
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				},
			}),
		},
		{
			name: "missing expiration",
			token: signToken(t, "test-secret", AccessClaims{
				Scope:    accessScope,
				TokenUse: tokenUseAccess,
				RegisteredClaims: jwt.RegisteredClaims{
					Subject:  "analyst",
					ID:       "session-1",
					Issuer:   "issuer",
					Audience: jwt.ClaimStrings{"audience"},
					IssuedAt: jwt.NewNumericDate(time.Now()),
				},
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			username, err := manager.ExtractUsername(tt.token)
			if !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("expected ErrInvalidToken, got username=%q err=%v", username, err)
			}
		})
	}
}

func TestJWTManagerRejectsInvalidApplicationClaims(t *testing.T) {
	manager := NewJWTManager("test-secret", time.Hour, time.Hour*24, "issuer", "audience")

	tests := []struct {
		name      string
		claims    AccessClaims
		expectErr error
	}{
		{
			name: "missing subject",
			claims: AccessClaims{
				Scope:    accessScope,
				TokenUse: tokenUseAccess,
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    "issuer",
					ID:        "session-1",
					Audience:  jwt.ClaimStrings{"audience"},
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				},
			},
			expectErr: ErrMissingSubject,
		},
		{
			name: "invalid scope",
			claims: AccessClaims{
				Scope:            "admin",
				TokenUse:         tokenUseAccess,
				RegisteredClaims: validRegisteredClaims("analyst", "session-1"),
			},
			expectErr: ErrInvalidScope,
		},
		{
			name: "invalid token use",
			claims: AccessClaims{
				Scope:            accessScope,
				TokenUse:         tokenUseRefresh,
				RegisteredClaims: validRegisteredClaims("analyst", "session-1"),
			},
			expectErr: ErrInvalidTokenUse,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := signToken(t, "test-secret", tt.claims)

			username, err := manager.ExtractUsername(token)
			if !errors.Is(err, tt.expectErr) {
				t.Fatalf("expected %v, got username=%q err=%v", tt.expectErr, username, err)
			}
		})
	}
}

func TestJWTManagerGeneratesAndValidatesRefreshTokens(t *testing.T) {
	manager := NewJWTManager("test-secret", time.Hour, time.Hour*24, "issuer", "audience")

	token, err := manager.GenerateRefreshToken("analyst", "refresh-session-1")
	if err != nil {
		t.Fatalf("expected refresh token generation to succeed: %v", err)
	}

	claims, err := manager.ExtractRefreshClaims(token)
	if err != nil {
		t.Fatalf("expected refresh token extraction to succeed: %v", err)
	}
	if claims.Subject != "analyst" {
		t.Fatalf("expected refresh username analyst, got %q", claims.Subject)
	}
	if claims.ID != "refresh-session-1" {
		t.Fatalf("expected refresh token id refresh-session-1, got %q", claims.ID)
	}
}

func TestSecurityErrorMessage(t *testing.T) {
	err := SecurityError{Message: "security failed"}

	if err.Error() != "security failed" {
		t.Fatalf("expected security failed, got %q", err.Error())
	}
}

func TestPermissionChecks(t *testing.T) {
	tests := []struct {
		name          string
		role          string
		wantIsAdmin   bool
		wantCanManage bool
	}{
		{
			name:          "admin",
			role:          model.RoleAdmin,
			wantIsAdmin:   true,
			wantCanManage: true,
		},
		{
			name:          "user",
			role:          model.RoleUser,
			wantIsAdmin:   false,
			wantCanManage: false,
		},
		{
			name:          "empty role",
			role:          "",
			wantIsAdmin:   false,
			wantCanManage: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsAdmin(tt.role); got != tt.wantIsAdmin {
				t.Fatalf("expected IsAdmin(%q)=%v, got %v", tt.role, tt.wantIsAdmin, got)
			}
			if got := CanManageVulnerabilities(tt.role); got != tt.wantCanManage {
				t.Fatalf("expected CanManageVulnerabilities(%q)=%v, got %v", tt.role, tt.wantCanManage, got)
			}
		})
	}
}

func signToken(t *testing.T, secret string, claims AccessClaims) string {
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
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
}
