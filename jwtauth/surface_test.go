// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2024-present Matt J. Stevenson and Contributors

package jwtauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0mjs/zinc"
	"github.com/golang-jwt/jwt/v5"
)

func TestKeyFuncAndClaims(t *testing.T) {
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "joe"}).SignedString([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	app := zinc.New()
	app.Use(New(Config{KeyFunc: func(*zinc.Context, *jwt.Token) (any, error) {
		return []byte("secret"), nil
	}}))
	app.Get("/private", func(c *zinc.Context) error {
		claims := MustClaims[jwt.MapClaims](c)
		return c.String(claims["sub"].(string))
	})

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.Header.Set(zinc.HeaderAuthorization, "Bearer "+signed)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "joe" {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestHeaderAndQueryExtractors(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?jwt=query-token", nil)
	req.Header.Set("X-JWT", "header-token")
	app := zinc.New()
	ctx := app.AcquireContext(httptest.NewRecorder(), req)
	defer app.ReleaseContext(ctx)

	if token, err := FromHeader("X-JWT")(ctx); err != nil || token != "header-token" {
		t.Fatalf("header token=%q err=%v", token, err)
	}
	if token, err := FromQuery("jwt")(ctx); err != nil || token != "query-token" {
		t.Fatalf("query token=%q err=%v", token, err)
	}
}
