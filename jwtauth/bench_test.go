// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024-present Matt J. Stevenson and Contributors

package jwtauth

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/0mjs/zinc"
	"github.com/golang-jwt/jwt/v5"
)

var benchSecret = []byte("benchmark-secret-key-with-enough-entropy")

func benchHMACKeyFunc(*zinc.Context, *jwt.Token) (any, error) {
	return benchSecret, nil
}

func benchSign(b *testing.B, method jwt.SigningMethod, claims jwt.Claims, key any) string {
	b.Helper()
	signed, err := jwt.NewWithClaims(method, claims).SignedString(key)
	if err != nil {
		b.Fatalf("sign: %v", err)
	}
	return signed
}

func benchApp(mw zinc.Middleware) *zinc.App {
	app := zinc.New()
	app.Use(mw)
	app.Get("/private", func(c *zinc.Context) error {
		return c.String("ok")
	})
	return app
}

// benchServe drives req through app on every iteration and checks the status.
func benchServe(b *testing.B, app *zinc.App, req *http.Request, want int) {
	b.Helper()
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	if rec.Code != want {
		b.Fatalf("status=%d want=%d body=%q", rec.Code, want, rec.Body.String())
	}

	b.ReportAllocs()
	for b.Loop() {
		app.ServeHTTP(httptest.NewRecorder(), req)
	}
}

func BenchmarkMiddleware(b *testing.B) {
	b.Run("HS256/MapClaims", func(b *testing.B) {
		app := benchApp(New(Config{
			KeyFunc: benchHMACKeyFunc,
			ParserOptions: []jwt.ParserOption{
				jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
			},
		}))
		token := benchSign(b, jwt.SigningMethodHS256, jwt.MapClaims{
			"sub":  "user-123",
			"role": "admin",
			"exp":  time.Now().Add(24 * time.Hour).Unix(),
		}, benchSecret)

		req := httptest.NewRequest(http.MethodGet, "/private", nil)
		req.Header.Set(zinc.HeaderAuthorization, "Bearer "+token)
		benchServe(b, app, req, http.StatusOK)
	})

	b.Run("HS256/TypedClaims", func(b *testing.B) {
		type claims struct {
			Role string `json:"role"`
			jwt.RegisteredClaims
		}
		app := benchApp(New(Config{
			KeyFunc: benchHMACKeyFunc,
			NewClaims: func(*zinc.Context) jwt.Claims {
				return &claims{}
			},
			Validate: func(_ *zinc.Context, token *jwt.Token) error {
				if token.Claims.(*claims).Role != "admin" {
					return zinc.ErrForbidden
				}
				return nil
			},
		}))
		token := benchSign(b, jwt.SigningMethodHS256, &claims{
			Role: "admin",
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   "user-1",
				Issuer:    "zinc",
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
		}, benchSecret)

		req := httptest.NewRequest(http.MethodGet, "/private", nil)
		req.Header.Set(zinc.HeaderAuthorization, "Bearer "+token)
		benchServe(b, app, req, http.StatusOK)
	})

	b.Run("RS256/MapClaims", func(b *testing.B) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			b.Fatalf("generate key: %v", err)
		}
		app := benchApp(New(Config{
			KeyFunc: func(*zinc.Context, *jwt.Token) (any, error) {
				return &privateKey.PublicKey, nil
			},
			ParserOptions: []jwt.ParserOption{
				jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
			},
		}))
		token := benchSign(b, jwt.SigningMethodRS256, jwt.MapClaims{
			"sub": "user-123",
			"exp": time.Now().Add(24 * time.Hour).Unix(),
		}, privateKey)

		req := httptest.NewRequest(http.MethodGet, "/private", nil)
		req.Header.Set(zinc.HeaderAuthorization, "Bearer "+token)
		benchServe(b, app, req, http.StatusOK)
	})

	b.Run("CookieFallback", func(b *testing.B) {
		app := benchApp(New(Config{
			Extractor: FromFirst(
				FromAuthorizationHeader("Bearer"),
				FromQuery("access_token"),
				FromCookie("access_token"),
			),
			KeyFunc: benchHMACKeyFunc,
		}))
		token := benchSign(b, jwt.SigningMethodHS256, jwt.MapClaims{"sub": "cookie-user"}, benchSecret)

		req := httptest.NewRequest(http.MethodGet, "/private", nil)
		req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
		benchServe(b, app, req, http.StatusOK)
	})

	b.Run("ParseTokenFunc", func(b *testing.B) {
		app := benchApp(New(Config{
			ParseTokenFunc: func(_ *zinc.Context, tokenString string) (*jwt.Token, error) {
				return &jwt.Token{
					Valid:  true,
					Method: jwt.SigningMethodHS256,
					Claims: jwt.MapClaims{"sub": tokenString},
				}, nil
			},
		}))

		req := httptest.NewRequest(http.MethodGet, "/private", nil)
		req.Header.Set(zinc.HeaderAuthorization, "Bearer opaque-token")
		benchServe(b, app, req, http.StatusOK)
	})
}

func BenchmarkMiddlewareRejects(b *testing.B) {
	app := benchApp(New(Config{
		KeyFunc: benchHMACKeyFunc,
		Realm:   "api",
	}))

	b.Run("MissingToken", func(b *testing.B) {
		req := httptest.NewRequest(http.MethodGet, "/private", nil)
		benchServe(b, app, req, http.StatusUnauthorized)
	})

	b.Run("MalformedHeader", func(b *testing.B) {
		req := httptest.NewRequest(http.MethodGet, "/private", nil)
		req.Header.Set(zinc.HeaderAuthorization, "Token abc")
		benchServe(b, app, req, http.StatusUnauthorized)
	})

	b.Run("InvalidSignature", func(b *testing.B) {
		token := benchSign(b, jwt.SigningMethodHS256, jwt.MapClaims{"sub": "user-123"}, []byte("wrong-secret"))
		req := httptest.NewRequest(http.MethodGet, "/private", nil)
		req.Header.Set(zinc.HeaderAuthorization, "Bearer "+token)
		benchServe(b, app, req, http.StatusUnauthorized)
	})

	b.Run("Expired", func(b *testing.B) {
		token := benchSign(b, jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "user-123",
			"exp": time.Now().Add(-time.Hour).Unix(),
		}, benchSecret)
		req := httptest.NewRequest(http.MethodGet, "/private", nil)
		req.Header.Set(zinc.HeaderAuthorization, "Bearer "+token)
		benchServe(b, app, req, http.StatusUnauthorized)
	})

	b.Run("GarbageToken", func(b *testing.B) {
		req := httptest.NewRequest(http.MethodGet, "/private", nil)
		req.Header.Set(zinc.HeaderAuthorization, "Bearer not.a.jwt")
		benchServe(b, app, req, http.StatusUnauthorized)
	})
}

func BenchmarkExtractors(b *testing.B) {
	const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEyMyJ9.signature"

	req := httptest.NewRequest(http.MethodGet, "/private?jwt="+token, nil)
	req.Header.Set(zinc.HeaderAuthorization, "Bearer "+token)
	req.Header.Set("X-JWT", token)
	req.AddCookie(&http.Cookie{Name: "session", Value: "abc"})
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})

	app := zinc.New()
	ctx := app.AcquireContext(httptest.NewRecorder(), req)
	b.Cleanup(func() { app.ReleaseContext(ctx) })

	cases := []struct {
		name      string
		extractor Extractor
	}{
		{"AuthorizationHeader", FromAuthorizationHeader("Bearer")},
		{"Header", FromHeader("X-JWT")},
		{"Query", FromQuery("jwt")},
		{"Cookie", FromCookie("access_token")},
		{"FirstFallback", FromFirst(
			FromHeader("X-Missing"),
			FromQuery("missing"),
			FromCookie("access_token"),
		)},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			got, err := tc.extractor(ctx)
			if err != nil || got != token {
				b.Fatalf("token=%q err=%v", got, err)
			}

			b.ReportAllocs()
			for b.Loop() {
				_, _ = tc.extractor(ctx)
			}
		})
	}
}
