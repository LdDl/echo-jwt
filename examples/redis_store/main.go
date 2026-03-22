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

const userAdmin = "admin"

var identityKey = "id"

func main() {
	e := echo.New()

	// Method 1: Using functional options with EnableRedisStore (recommended)
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

			if (userID == userAdmin && password == userAdmin) ||
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
			if v, ok := data.(*User); ok && v.UserName == userAdmin {
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

	// Configure Redis using functional options
	middleware.EnableRedisStore(
		jwt.WithRedisAddr("localhost:6379"),
		jwt.WithRedisCache(64*1024*1024, 30*time.Second), // 64MB client-side cache, 30s TTL
	)

	authMiddleware, err := jwt.New(middleware)
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
	auth.GET("/store-info", storeInfoHandler())

	log.Println("Server starting on :8000")
	log.Println("Using functional options Redis configuration")
	log.Println("Alternative methods shown below as comments:")

	srv := &http.Server{
		Addr:              ":8000",
		Handler:           e,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
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

// storeInfoHandler provides information about the current token store
func storeInfoHandler() echo.HandlerFunc {
	return func(c *echo.Context) error {
		return c.JSON(200, map[string]interface{}{
			"configuration": "functional_options",
			"redis_enabled": true,
			"message":       "Using functional options pattern for Redis configuration",
		})
	}
}
