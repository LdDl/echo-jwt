package main

import (
	"log"
	"net/http"
	"time"

	jwt "github.com/LopanovCo/echo-jwt"
	"github.com/labstack/echo/v5"
	gojwt "github.com/golang-jwt/jwt/v5"
)

type User struct {
	UserName  string `json:"username"`
	Password  string `json:"password"`
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
}

var identityKey = "id"

func main() {
	e := echo.New()

	// Create JWT middleware configuration
	middleware := &jwt.EchoJWTMiddleware{
		Realm:       "test zone",
		Key:         []byte("secret key"),
		Timeout:     time.Hour,
		MaxRefresh:  time.Hour,
		IdentityKey: identityKey,

		PayloadFunc: func(data any) gojwt.MapClaims {
			if v, ok := data.(*User); ok {
				return gojwt.MapClaims{
					identityKey: v.UserName,
				}
			}
			return gojwt.MapClaims{}
		},

		IdentityHandler: func(c *echo.Context) any {
			claims := jwt.ExtractClaims(c)
			return &User{
				UserName: claims[identityKey].(string),
			}
		},

		Authenticator: func(c *echo.Context) (any, error) {
			var loginVals User
			if err := c.Bind(&loginVals); err != nil {
				return "", jwt.ErrMissingLoginValues
			}
			userID := loginVals.UserName
			password := loginVals.Password

			if (userID == "admin" && password == "admin") ||
				(userID == "test" && password == "test") {
				return &User{
					UserName:  userID,
					LastName:  "Bo-Yi",
					FirstName: "Wu",
				}, nil
			}

			return nil, jwt.ErrFailedAuthentication
		},

		Authorizer: func(c *echo.Context, data any) bool {
			if v, ok := data.(*User); ok && v.UserName == "admin" {
				return true
			}
			return false
		},

		Unauthorized: func(c *echo.Context, code int, message string) {
			c.JSON(code, map[string]interface{}{
				"code":    code,
				"message": message,
			})
		},

		TokenLookup:   "header: Authorization, query: token, cookie: jwt",
		TokenHeadName: "Bearer",
		TimeFunc:      time.Now,
	}

	// Configure Redis store using functional options pattern
	middleware.EnableRedisStore(
		jwt.WithRedisCache(64*1024*1024, 30*time.Second), // 64MB cache, 30s TTL
	)

	// Create the JWT middleware
	authMiddleware, err := jwt.New(middleware)
	// Alternative initialization methods using functional options:
	//
	// Method 1: Simple enable with defaults
	// }.EnableRedisStore())
	//
	// Method 2: Enable with custom address
	// }.EnableRedisStore(jwt.WithRedisAddr("redis:6379")))
	//
	// Method 3: Enable with full options
	// }.EnableRedisStore(
	//     jwt.WithRedisAddr("localhost:6379"),
	//     jwt.WithRedisAuth("", 0),
	//     jwt.WithRedisCache(128*1024*1024, time.Minute),
	// ))
	//
	// Method 4: Enable with comprehensive configuration
	// }.EnableRedisStore(
	//     jwt.WithRedisAddr("localhost:6379"),
	//     jwt.WithRedisAuth("password", 1),
	//     jwt.WithRedisCache(128*1024*1024, time.Minute),
	//     jwt.WithRedisPool(20, time.Hour, 2*time.Hour),
	//     jwt.WithRedisKeyPrefix("myapp:jwt:"),
	// ))
	//
	// Method 5: Enable with TLS configuration (for secure Redis connections)
	// tlsConfig := &tls.Config{
	//     MinVersion: tls.VersionTLS12,
	//     // Add your certificates here if needed
	// }
	// }.EnableRedisStore(
	//     jwt.WithRedisAddr("redis.example.com:6380"),
	//     jwt.WithRedisAuth("password", 0),
	//     jwt.WithRedisTLS(tlsConfig),
	// ))
	if err != nil {
		log.Fatal("JWT Error:" + err.Error())
	}

	// When you use jwt.New(), the function is already automatically called for checking,
	// which means you don't need to call it again.
	errInit := authMiddleware.MiddlewareInit()
	if errInit != nil {
		log.Fatal("authMiddleware.MiddlewareInit() Error:" + errInit.Error())
	}

	e.POST("/login", authMiddleware.LoginHandler)

	auth := e.Group("/auth")
	// Refresh time can be longer than token timeout
	auth.GET("/refresh_token", authMiddleware.RefreshHandler)
	auth.Use(authMiddleware.MiddlewareFunc())
	auth.GET("/hello", helloHandler)

	log.Println("Server starting on :8000")
	log.Println("Redis store is enabled - will fall back to memory if Redis is not available")
	if err := http.ListenAndServe(":8000", e); err != nil {
		log.Fatal(err)
	}
}

func helloHandler(c *echo.Context) error {
	claims := jwt.ExtractClaims(c)
	user := c.Get(identityKey)
	return c.JSON(200, map[string]interface{}{
		"userID":   claims[identityKey],
		"userName": user.(*User).UserName,
		"text":     "Hello World.",
	})
}
