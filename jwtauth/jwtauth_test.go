// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024-present Matt J. Stevenson and Contributors

package jwtauth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/0mjs/zinc"
	"github.com/golang-jwt/jwt/v5"
)

func TestJWTMiddlewareWithMapClaims(t *testing.T) {
	app := zinc.New()
	app.Use(New(Config{
		KeyFunc: func(*zinc.Context, *jwt.Token) (any, error) {
			return []byte("secret"), nil
		},
		ParserOptions: []jwt.ParserOption{
			jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		},
	}))
	app.Get("/private", func(c *zinc.Context) error {
		token := MustGet(c)
		claims := MustClaims[jwt.MapClaims](c)
		return c.JSON(zinc.Map{
			"alg": token.Method.Alg(),
			"sub": claims["sub"],
			"raw": MustGet(c).Raw,
		})
	})

	tokenString := mustSignedStringJWT(t, jwt.MapClaims{
		"sub": "user-123",
	}, []byte("secret"))

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.Header.Set(zinc.HeaderAuthorization, "Bearer "+tokenString)
	rec := httptest.NewRecorder()

	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if body != `{"alg":"HS256","raw":"`+tokenString+`","sub":"user-123"}`+"\n" {
		t.Fatalf("body=%q", body)
	}
}

func TestJWTMiddlewareWithTypedClaims(t *testing.T) {
	type claims struct {
		Role string `json:"role"`
		jwt.RegisteredClaims
	}

	app := zinc.New()
	app.Use(New(Config{
		KeyFunc: func(*zinc.Context, *jwt.Token) (any, error) {
			return []byte("secret"), nil
		},
		NewClaims: func(*zinc.Context) jwt.Claims {
			return &claims{}
		},
	}))
	app.Get("/private", func(c *zinc.Context) error {
		got := MustClaims[*claims](c)
		return c.String(got.Role + ":" + got.Subject)
	})

	tokenString := mustSignedStringJWT(t, &claims{
		Role: "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-1",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}, []byte("secret"))

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.Header.Set(zinc.HeaderAuthorization, "Bearer "+tokenString)
	rec := httptest.NewRecorder()

	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "admin:user-1" {
		t.Fatalf("body=%q", rec.Body.String())
	}
}

func TestJWTMiddlewareMissingToken(t *testing.T) {
	app := zinc.New()
	app.Use(New(Config{
		KeyFunc: func(*zinc.Context, *jwt.Token) (any, error) {
			return []byte("secret"), nil
		},
		Realm: "api",
	}))
	app.Get("/private", func(c *zinc.Context) error {
		return c.String("ok")
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
	if rec.Body.String() != `{"error":{"status":401,"message":"Unauthorized"}}`+"\n" {
		t.Fatalf("body=%q", rec.Body.String())
	}
	if got := rec.Header().Get(zinc.HeaderWWWAuthenticate); got != `Bearer realm="api"` {
		t.Fatalf("challenge=%q", got)
	}
}

func TestJWTMiddlewareMalformedHeader(t *testing.T) {
	app := zinc.New()
	app.Use(New(Config{
		KeyFunc: func(*zinc.Context, *jwt.Token) (any, error) {
			return []byte("secret"), nil
		},
	}))
	app.Get("/private", func(c *zinc.Context) error {
		return c.String("ok")
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.Header.Set(zinc.HeaderAuthorization, "Token abc")
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
	if got := rec.Header().Get(zinc.HeaderWWWAuthenticate); got != `Bearer error="invalid_request"` {
		t.Fatalf("challenge=%q", got)
	}
}

func TestJWTMiddlewareInvalidToken(t *testing.T) {
	app := zinc.New()
	app.Use(New(Config{
		KeyFunc: func(*zinc.Context, *jwt.Token) (any, error) {
			return []byte("secret"), nil
		},
	}))
	app.Get("/private", func(c *zinc.Context) error {
		return c.String("ok")
	})

	tokenString := mustSignedStringJWT(t, jwt.MapClaims{
		"sub": "user-123",
	}, []byte("wrong-secret"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.Header.Set(zinc.HeaderAuthorization, "Bearer "+tokenString)
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
	if got := rec.Header().Get(zinc.HeaderWWWAuthenticate); got != `Bearer error="invalid_token"` {
		t.Fatalf("challenge=%q", got)
	}
}

func TestJWTMiddlewareFromFirst(t *testing.T) {
	app := zinc.New()
	app.Use(New(Config{
		Extractor: FromFirst(
			FromAuthorizationHeader("Bearer"),
			FromCookie("access_token"),
		),
		KeyFunc: func(*zinc.Context, *jwt.Token) (any, error) {
			return []byte("secret"), nil
		},
	}))
	app.Get("/private", func(c *zinc.Context) error {
		return c.String(MustGet(c).Raw)
	})

	tokenString := mustSignedStringJWT(t, jwt.MapClaims{
		"sub": "cookie-user",
	}, []byte("secret"))

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: tokenString})
	rec := httptest.NewRecorder()

	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != tokenString {
		t.Fatalf("body=%q", rec.Body.String())
	}
}

func TestJWTMiddlewareValidateCanRejectWithForbidden(t *testing.T) {
	app := zinc.New()
	app.Use(New(Config{
		KeyFunc: func(*zinc.Context, *jwt.Token) (any, error) {
			return []byte("secret"), nil
		},
		Validate: func(_ *zinc.Context, token *jwt.Token) error {
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok || claims["role"] != "admin" {
				return zinc.ErrForbidden
			}
			return nil
		},
	}))
	app.Get("/private", func(c *zinc.Context) error {
		return c.String("ok")
	})

	tokenString := mustSignedStringJWT(t, jwt.MapClaims{
		"role": "member",
	}, []byte("secret"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.Header.Set(zinc.HeaderAuthorization, "Bearer "+tokenString)
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rec.Code)
	}
	if got := rec.Header().Get(zinc.HeaderWWWAuthenticate); got != "" {
		t.Fatalf("challenge=%q", got)
	}
}

func TestJWTMiddlewareCustomErrorHandler(t *testing.T) {
	var gotErr error

	app := zinc.New()
	app.Use(New(Config{
		KeyFunc: func(*zinc.Context, *jwt.Token) (any, error) {
			return []byte("secret"), nil
		},
		ErrorHandler: func(c *zinc.Context, err error) error {
			gotErr = err
			return c.Status(http.StatusTeapot).String("bad token")
		},
	}))
	app.Get("/private", func(c *zinc.Context) error {
		return c.String("ok")
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Fatalf("status=%d", rec.Code)
	}
	if rec.Body.String() != "bad token" {
		t.Fatalf("body=%q", rec.Body.String())
	}
	if !errors.Is(gotErr, ErrTokenMissing) {
		t.Fatalf("err=%v", gotErr)
	}
}

func TestJWTMiddlewareParseTokenFunc(t *testing.T) {
	app := zinc.New()
	app.Use(New(Config{
		ParseTokenFunc: func(_ *zinc.Context, tokenString string) (*jwt.Token, error) {
			return &jwt.Token{
				Valid:  true,
				Method: jwt.SigningMethodHS256,
				Claims: jwt.MapClaims{"name": tokenString},
			}, nil
		},
	}))
	app.Get("/private", func(c *zinc.Context) error {
		got := MustClaims[jwt.MapClaims](c)
		return c.String(got["name"].(string))
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/private?token=alice", nil)
	req.Header.Set(zinc.HeaderAuthorization, "Bearer alice")
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "alice" {
		t.Fatalf("body=%q", rec.Body.String())
	}
}

func TestJWTMiddlewarePanicsWithoutParserOrKeyFunc(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()

	_ = New(Config{})
}

func TestJWTMustAccessorsPanicWhenMissing(t *testing.T) {
	app := zinc.New()
	c := app.AcquireContext(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	defer app.ReleaseContext(c)

	assertPanicsJWT(t, func() {
		_ = MustGet(c)
	})
	assertPanicsJWT(t, func() {
		_ = MustGet(c).Raw
	})
	assertPanicsJWT(t, func() {
		_ = MustClaims[jwt.MapClaims](c)
	})
}

func mustSignedStringJWT(t *testing.T, claims jwt.Claims, key []byte) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("signed string error: %v", err)
	}
	return tokenString
}

func assertPanicsJWT(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	fn()
}
