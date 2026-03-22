module github.com/LdDl/echo-jwt/examples/oauth_sso

go 1.25.0

replace github.com/LdDl/echo-jwt => ../../

require (
	github.com/LdDl/echo-jwt v0.0.0
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/joho/godotenv v1.5.1
	github.com/labstack/echo/v5 v5.0.4
	golang.org/x/oauth2 v0.34.0
)

require (
	cloud.google.com/go/compute/metadata v0.3.0 // indirect
	github.com/redis/rueidis v1.0.73 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
)
