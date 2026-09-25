# Zinc contrib

Middleware for [Zinc](https://github.com/0mjs/zinc) that needs a third-party library. Zinc's own middleware, under `github.com/0mjs/zinc/middleware`, depends only on the standard library; anything with a dependency lives here instead, so you only download what you use.

Each package is its own Go module, versioned on its own with a path-prefixed tag such as `jwtauth/v0.4.0`.

| Package | What it does | Depends on |
|---|---|---|
| [`jwtauth`](./jwtauth) | Authenticates requests with JSON Web Tokens | [`github.com/golang-jwt/jwt/v5`](https://github.com/golang-jwt/jwt) |

## Install

```sh
go get github.com/0mjs/contrib/jwtauth
```

```go
import (
	"github.com/0mjs/contrib/jwtauth"
	"github.com/golang-jwt/jwt/v5"
)

api := app.Group("/api", jwtauth.New(jwtauth.Config{
	KeyFunc: func(_ *zinc.Context, token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", token.Header["alg"])
		}
		return signingKey, nil
	},
}))
```

See the [JWT docs](https://zinc.carbonsoft.sh/middleware/jwtauth/) for configuration.

## Status

These packages target Zinc 0.4, which is not tagged yet. Until it is, each module builds against a sibling checkout of Zinc (`replace github.com/0mjs/zinc => ../../zinc`), so clone both repositories into the same directory to work on them.

## License

[MIT](./LICENSE)
