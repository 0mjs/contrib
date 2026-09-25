module github.com/0mjs/contrib/jwtauth

go 1.25.0

require (
	github.com/0mjs/zinc v0.3.0
	github.com/golang-jwt/jwt/v5 v5.3.1
)

require (
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// Until Zinc 0.4.0 is tagged, build against a sibling checkout of Zinc.
// Remove this line when requiring the release.
replace github.com/0mjs/zinc => ../../zinc
