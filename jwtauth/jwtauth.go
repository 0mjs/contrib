// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024-present Matt J. Stevenson and Contributors

// Package jwtauth authenticates requests with JSON Web Tokens, verified by
// github.com/golang-jwt/jwt.
package jwtauth

import (
	"errors"
	"fmt"
	"net/http"
	"net/textproto"
	"strings"

	"github.com/0mjs/zinc"
	"github.com/golang-jwt/jwt/v5"
)

var (
	// JWT errors separate absent, malformed, and cryptographically invalid input.
	ErrTokenMissing   = errors.New("jwtauth: token missing")
	ErrTokenMalformed = errors.New("jwtauth: token malformed")
	ErrTokenInvalid   = errors.New("jwtauth: token invalid")
)

// Extractor retrieves a serialized token from a request.
type Extractor func(*zinc.Context) (string, error)

// KeyFunc resolves the verification key for a parsed token.
type KeyFunc func(*zinc.Context, *jwt.Token) (any, error)

// ParseTokenFunc parses and cryptographically verifies a serialized token.
type ParseTokenFunc func(*zinc.Context, string) (*jwt.Token, error)

// ValidateFunc applies application-specific validation after verification.
type ValidateFunc func(*zinc.Context, *jwt.Token) error

// Config controls extraction, parsing, validation, and error handling.
type Config struct {
	Extractor      Extractor
	NewClaims      func(*zinc.Context) jwt.Claims
	KeyFunc        KeyFunc
	ParseTokenFunc ParseTokenFunc
	ParserOptions  []jwt.ParserOption
	Validate       ValidateFunc
	SuccessHandler zinc.HandlerFunc
	ErrorHandler   func(*zinc.Context, error) error
	Realm          string
}

type jwtContextKey int

const (
	jwtTokenContextKey jwtContextKey = iota
	jwtClaimsContextKey
)

// defaultConfig extracts Bearer tokens from Authorization.
func defaultConfig() Config {
	return Config{
		Extractor: FromAuthorizationHeader("Bearer"),
		SuccessHandler: func(c *zinc.Context) error {
			return c.Next()
		},
	}
}

// New verifies a token on each request, accepts only tokens marked valid by
// golang-jwt, and then applies Config.Validate before publishing claims.
// Config.KeyFunc or Config.ParseTokenFunc is required.
func New(configs ...Config) zinc.Middleware {
	if len(configs) > 1 {
		panic("jwtauth: New takes at most one Config")
	}
	var config Config
	if len(configs) == 1 {
		config = configs[0]
	}
	cfg := resolveJWTConfig(config)

	return func(c *zinc.Context) error {
		tokenString, err := cfg.Extractor(c)
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}

		token, err := cfg.ParseTokenFunc(c, tokenString)
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}
		if token == nil || !token.Valid {
			return cfg.ErrorHandler(c, ErrTokenInvalid)
		}

		if cfg.Validate != nil {
			if err := cfg.Validate(c, token); err != nil {
				return cfg.ErrorHandler(c, err)
			}
		}

		c.Set(jwtTokenContextKey, token)
		c.Set(jwtClaimsContextKey, token.Claims)
		return cfg.SuccessHandler(c)
	}
}

// FromAuthorizationHeader extracts a token using an authorization scheme.
func FromAuthorizationHeader(scheme string) Extractor {
	scheme = strings.TrimSpace(scheme)
	if scheme == "" {
		scheme = "Bearer"
	}
	return FromHeaderPrefix(zinc.HeaderAuthorization, scheme+" ")
}

// FromHeader extracts an unprefixed token from header.
func FromHeader(header string) Extractor {
	header = textproto.CanonicalMIMEHeaderKey(header)

	return func(c *zinc.Context) (string, error) {
		value := strings.TrimSpace(c.Header(header))
		if value == "" {
			return "", fmt.Errorf("%w: %s header", ErrTokenMissing, header)
		}
		return value, nil
	}
}

// FromHeaderPrefix extracts a token after a case-insensitive prefix.
func FromHeaderPrefix(header, prefix string) Extractor {
	header = textproto.CanonicalMIMEHeaderKey(header)
	if prefix == "" {
		return FromHeader(header)
	}

	return func(c *zinc.Context) (string, error) {
		value := strings.TrimSpace(c.Header(header))
		if value == "" {
			return "", fmt.Errorf("%w: %s header", ErrTokenMissing, header)
		}
		if len(value) <= len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
			return "", fmt.Errorf("%w: %s header", ErrTokenMalformed, header)
		}
		token := strings.TrimSpace(value[len(prefix):])
		if token == "" {
			return "", fmt.Errorf("%w: %s header", ErrTokenMalformed, header)
		}
		return token, nil
	}
}

// FromCookie extracts a token from a cookie.
func FromCookie(name string) Extractor {
	return func(c *zinc.Context) (string, error) {
		cookie, err := c.Cookie(name)
		if err != nil {
			if errors.Is(err, http.ErrNoCookie) {
				return "", fmt.Errorf("%w: %s cookie", ErrTokenMissing, name)
			}
			return "", err
		}
		if cookie.Value == "" {
			return "", fmt.Errorf("%w: %s cookie", ErrTokenMalformed, name)
		}
		return cookie.Value, nil
	}
}

// FromQuery extracts a token from a query parameter.
func FromQuery(name string) Extractor {
	return func(c *zinc.Context) (string, error) {
		value := c.Query(name)
		if value == "" {
			return "", fmt.Errorf("%w: %s query value", ErrTokenMissing, name)
		}
		return value, nil
	}
}

// FromFirst falls back only for missing tokens; malformed tokens stop lookup.
func FromFirst(extractors ...Extractor) Extractor {
	list := append([]Extractor(nil), extractors...)

	return func(c *zinc.Context) (string, error) {
		var lastMissing error
		for _, extractor := range list {
			if extractor == nil {
				continue
			}
			token, err := extractor(c)
			if err == nil {
				return token, nil
			}
			if errors.Is(err, ErrTokenMissing) {
				lastMissing = err
				continue
			}
			return "", err
		}
		if lastMissing != nil {
			return "", lastMissing
		}
		return "", ErrTokenMissing
	}
}

// Get returns the verified token for the current request.
func Get(c *zinc.Context) (*jwt.Token, bool) {
	if c == nil {
		return nil, false
	}
	value, ok := c.Get(jwtTokenContextKey)
	if !ok {
		return nil, false
	}
	token, ok := value.(*jwt.Token)
	return token, ok
}

// MustGet returns the verified token or panics when absent.
func MustGet(c *zinc.Context) *jwt.Token {
	token, ok := Get(c)
	if !ok {
		panic("jwtauth: token not found")
	}
	return token
}

// Claims returns verified claims as T.
func Claims[T any](c *zinc.Context) (T, bool) {
	var zero T
	if c == nil {
		return zero, false
	}
	value, ok := c.Get(jwtClaimsContextKey)
	if !ok {
		return zero, false
	}
	claims, ok := value.(T)
	if !ok {
		return zero, false
	}
	return claims, true
}

// MustClaims returns verified claims as T or panics on absence or mismatch.
func MustClaims[T any](c *zinc.Context) T {
	claims, ok := Claims[T](c)
	if !ok {
		panic("jwtauth: claims not found")
	}
	return claims
}

func resolveJWTConfig(config Config) Config {
	cfg := defaultConfig()

	if config.Extractor != nil {
		cfg.Extractor = config.Extractor
	}
	if config.Validate != nil {
		cfg.Validate = config.Validate
	}
	if config.SuccessHandler != nil {
		cfg.SuccessHandler = config.SuccessHandler
	}
	if config.Realm != "" {
		cfg.Realm = config.Realm
	}
	cfg.ParserOptions = append([]jwt.ParserOption(nil), config.ParserOptions...)

	if config.ParseTokenFunc != nil {
		cfg.ParseTokenFunc = config.ParseTokenFunc
	} else {
		if config.KeyFunc == nil {
			panic("jwtauth: KeyFunc or ParseTokenFunc is required")
		}
		claimsFactory := config.NewClaims
		if claimsFactory == nil {
			claimsFactory = func(*zinc.Context) jwt.Claims {
				return jwt.MapClaims{}
			}
		}
		keyFunc := config.KeyFunc
		options := append([]jwt.ParserOption(nil), config.ParserOptions...)
		cfg.ParseTokenFunc = func(c *zinc.Context, tokenString string) (*jwt.Token, error) {
			claims := claimsFactory(c)
			if claims == nil {
				claims = jwt.MapClaims{}
			}
			return jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
				return keyFunc(c, token)
			}, options...)
		}
	}

	if config.ErrorHandler != nil {
		cfg.ErrorHandler = config.ErrorHandler
	} else {
		realm := cfg.Realm
		cfg.ErrorHandler = func(c *zinc.Context, err error) error {
			var httpErr *zinc.HTTPError
			if errors.As(err, &httpErr) && httpErr.Code != http.StatusUnauthorized {
				return err
			}

			c.SetHeader(zinc.HeaderWWWAuthenticate, buildJWTBearerChallenge(realm, err))

			if errors.As(err, &httpErr) {
				return err
			}
			return zinc.ErrUnauthorized
		}
	}

	return cfg
}

func buildJWTBearerChallenge(realm string, err error) string {
	params := make([]string, 0, 2)
	if realm != "" {
		params = append(params, fmt.Sprintf(`realm=%q`, realm))
	}
	if code := jwtChallengeErrorCode(err); code != "" {
		params = append(params, fmt.Sprintf(`error=%q`, code))
	}
	if len(params) == 0 {
		return "Bearer"
	}
	return "Bearer " + strings.Join(params, ", ")
}

func jwtChallengeErrorCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrTokenMissing):
		return ""
	case errors.Is(err, ErrTokenMalformed):
		return "invalid_request"
	default:
		return "invalid_token"
	}
}
