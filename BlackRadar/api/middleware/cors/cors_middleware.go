// Package cors provides explicit allowlist-based CORS middleware.
package cors

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const defaultPreflightMaxAge = 10 * time.Minute

// Config defines the cross-origin policy for the API.
type Config struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposedHeaders   []string
	AllowCredentials bool
	MaxAge           time.Duration
}

// New creates CORS middleware from an explicit allowlist.
//
// Configuration errors are returned during application startup rather than
// being discovered while handling requests.
func New(cfg Config) (gin.HandlerFunc, error) {
	policy, err := buildPolicy(cfg)
	if err != nil {
		return nil, err
	}

	return policy.middleware(), nil
}

type policy struct {
	allowedOrigins   map[string]struct{}
	allowedMethods   map[string]struct{}
	allowedHeaders   map[string]struct{}
	methodsHeader    string
	headersHeader    string
	exposedHeader    string
	allowCredentials bool
	maxAgeSeconds    int64
}

// buildPolicy validates configuration and prepares normalized lookup sets and headers.
func buildPolicy(cfg Config) (policy, error) {
	origins, err := buildOriginSet(cfg.AllowedOrigins)
	if err != nil {
		return policy{}, err
	}

	methods := normalizeMethods(cfg.AllowedMethods)
	if len(methods) == 0 {
		methods = []string{
			http.MethodDelete,
			http.MethodGet,
			http.MethodOptions,
			http.MethodPatch,
			http.MethodPost,
			http.MethodPut,
		}
	}

	headers := normalizeHeaders(cfg.AllowedHeaders)
	if len(headers) == 0 {
		headers = []string{
			"Authorization",
			"Content-Type",
		}
	}

	exposedHeaders := normalizeHeaders(cfg.ExposedHeaders)

	maxAge := cfg.MaxAge
	if maxAge == 0 {
		maxAge = defaultPreflightMaxAge
	}
	if maxAge < 0 {
		return policy{}, ErrInvalidCORSMaxAge
	}

	return policy{
		allowedOrigins:   origins,
		allowedMethods:   toSet(methods),
		allowedHeaders:   toCaseInsensitiveSet(headers),
		methodsHeader:    strings.Join(methods, ", "),
		headersHeader:    strings.Join(headers, ", "),
		exposedHeader:    strings.Join(exposedHeaders, ", "),
		allowCredentials: cfg.AllowCredentials,
		maxAgeSeconds:    int64(maxAge / time.Second),
	}, nil
}

// middleware returns the Gin handler that applies the prepared CORS policy.
func (policy policy) middleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		origin := strings.TrimSpace(ctx.GetHeader("Origin"))
		if origin == "" {
			ctx.Next()
			return
		}

		if _, allowed := policy.allowedOrigins[origin]; !allowed {
			if ctx.Request.Method == http.MethodOptions {
				ctx.AbortWithStatus(http.StatusForbidden)
				return
			}

			ctx.Next()
			return
		}

		setVaryHeader(ctx.Writer.Header(), "Origin")
		ctx.Header("Access-Control-Allow-Origin", origin)
		if policy.allowCredentials {
			ctx.Header("Access-Control-Allow-Credentials", "true")
		}
		if policy.exposedHeader != "" {
			ctx.Header("Access-Control-Expose-Headers", policy.exposedHeader)
		}

		if ctx.Request.Method != http.MethodOptions {
			ctx.Next()
			return
		}

		policy.handlePreflight(ctx)
	}
}

// handlePreflight validates and answers an approved origin's preflight request.
func (policy policy) handlePreflight(ctx *gin.Context) {
	requestedMethod := strings.ToUpper(strings.TrimSpace(ctx.GetHeader("Access-Control-Request-Method")))
	if requestedMethod == "" {
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}
	if _, allowed := policy.allowedMethods[requestedMethod]; !allowed {
		ctx.AbortWithStatus(http.StatusForbidden)
		return
	}

	requestedHeaders := parseHeaderList(ctx.GetHeader("Access-Control-Request-Headers"))
	for _, header := range requestedHeaders {
		if _, allowed := policy.allowedHeaders[strings.ToLower(header)]; !allowed {
			ctx.AbortWithStatus(http.StatusForbidden)
			return
		}
	}

	setVaryHeader(ctx.Writer.Header(), "Access-Control-Request-Method")
	setVaryHeader(ctx.Writer.Header(), "Access-Control-Request-Headers")
	ctx.Header("Access-Control-Allow-Methods", policy.methodsHeader)
	ctx.Header("Access-Control-Allow-Headers", policy.headersHeader)
	if policy.maxAgeSeconds > 0 {
		ctx.Header("Access-Control-Max-Age", fmt.Sprintf("%d", policy.maxAgeSeconds))
	}

	ctx.AbortWithStatus(http.StatusNoContent)
}

// buildOriginSet validates configured origins and returns an exact-match allowlist.
func buildOriginSet(origins []string) (map[string]struct{}, error) {
	allowed := make(map[string]struct{}, len(origins))
	for _, rawOrigin := range origins {
		origin := strings.TrimSpace(rawOrigin)
		if origin == "" {
			continue
		}
		if origin == "*" {
			return nil, ErrCORSWildcardOrigin
		}
		if origin == "null" {
			return nil, ErrCORSNullOrigin
		}
		if err := validateOrigin(origin); err != nil {
			return nil, err
		}

		allowed[origin] = struct{}{}
	}

	return allowed, nil
}

// validateOrigin ensures an origin is a bare HTTP or HTTPS origin.
func validateOrigin(origin string) error {
	parsed, err := url.ParseRequestURI(origin)
	if err != nil {
		return fmt.Errorf("%w: %q: %v", ErrInvalidCORSOrigin, origin, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%w: %q must use http or https", ErrInvalidCORSOrigin, origin)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%w: %q must include a host", ErrInvalidCORSOrigin, origin)
	}
	if parsed.User != nil ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") {
		return fmt.Errorf("%w: %q must not include credentials, path, query, or fragment", ErrInvalidCORSOrigin, origin)
	}

	return nil
}

// normalizeMethods trims, uppercases, deduplicates, and sorts HTTP methods.
func normalizeMethods(methods []string) []string {
	normalized := make([]string, 0, len(methods))
	seen := make(map[string]struct{}, len(methods))
	for _, method := range methods {
		method = strings.ToUpper(strings.TrimSpace(method))
		if method == "" {
			continue
		}
		if _, exists := seen[method]; exists {
			continue
		}

		seen[method] = struct{}{}
		normalized = append(normalized, method)
	}

	sort.Strings(normalized)
	return normalized
}

// normalizeHeaders trims, canonicalizes, deduplicates, and sorts HTTP headers.
func normalizeHeaders(headers []string) []string {
	normalized := make([]string, 0, len(headers))
	seen := make(map[string]struct{}, len(headers))
	for _, header := range headers {
		header = http.CanonicalHeaderKey(strings.TrimSpace(header))
		if header == "" {
			continue
		}

		lowercase := strings.ToLower(header)
		if _, exists := seen[lowercase]; exists {
			continue
		}

		seen[lowercase] = struct{}{}
		normalized = append(normalized, header)
	}

	sort.Strings(normalized)
	return normalized
}

// parseHeaderList parses a comma-separated request header list.
func parseHeaderList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	parts := strings.Split(value, ",")
	headers := make([]string, 0, len(parts))
	for _, part := range parts {
		header := http.CanonicalHeaderKey(strings.TrimSpace(part))
		if header != "" {
			headers = append(headers, header)
		}
	}

	return headers
}

// toSet converts normalized values into an exact-match set.
func toSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

// toCaseInsensitiveSet converts normalized values into a lowercase lookup set.
func toCaseInsensitiveSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[strings.ToLower(value)] = struct{}{}
	}
	return result
}

// setVaryHeader adds a Vary value unless an equivalent value already exists.
func setVaryHeader(headers http.Header, value string) {
	for _, existing := range headers.Values("Vary") {
		for _, entry := range strings.Split(existing, ",") {
			if strings.EqualFold(strings.TrimSpace(entry), value) {
				return
			}
		}
	}

	headers.Add("Vary", value)
}
