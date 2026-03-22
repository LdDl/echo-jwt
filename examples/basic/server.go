package main

import (
	"log"
	"net/http"
	"os"
	"time"

	jwt "github.com/LopanovCo/echo-jwt"
	"github.com/labstack/echo/v5"
	gojwt "github.com/golang-jwt/jwt/v5"
)

type login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

const userAdmin = "admin"

var (
	identityKey = "id"
	port        string
)

// User demo
type User struct {
	UserName  string
	FirstName string
	LastName  string
}

func init() {
	port = os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}
}

func main() {
	e := echo.New()
	// the jwt middleware
	authMiddleware, err := jwt.New(initParams())
	if err != nil {
		log.Fatal("JWT Error:" + err.Error())
	}

	// initialize middleware
	errInit := authMiddleware.MiddlewareInit()
	if errInit != nil {
		log.Fatal("authMiddleware.MiddlewareInit() Error:" + errInit.Error())
	}

	// register route
	registerRoute(e, authMiddleware)

	// start http server with proper timeouts
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           e,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err = srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func registerRoute(e *echo.Echo, handle *jwt.EchoJWTMiddleware) {
	// Public routes
	e.POST("/login", handle.LoginHandler)
	e.POST("/refresh", handle.RefreshHandler) // RFC 6749 compliant refresh endpoint

	// Protected routes
	auth := e.Group("/auth")
	auth.Use(handle.MiddlewareFunc())
	auth.GET("/hello", helloHandler)
	auth.POST("/logout", handle.LogoutHandler) // Logout with refresh token revocation
}

func initParams() *jwt.EchoJWTMiddleware {
	return &jwt.EchoJWTMiddleware{
		Realm:       "test zone",
		Key:         []byte("secret key"),
		Timeout:     time.Hour,
		MaxRefresh:  time.Hour,
		IdentityKey: identityKey,
		PayloadFunc: payloadFunc(),

		IdentityHandler: identityHandler(),
		Authenticator:   authenticator(),
		Authorizer:      authorizator(),
		Unauthorized:    unauthorized(),
		LogoutResponse:  logoutResponse(),
		TokenLookup:     "header: Authorization, query: token, cookie: jwt",
		// TokenLookup: "query:token",
		// TokenLookup: "cookie:token",
		TokenHeadName: "Bearer",
		TimeFunc:      time.Now,
	}
}

func payloadFunc() func(data any) gojwt.MapClaims {
	return func(data any) gojwt.MapClaims {
		if v, ok := data.(*User); ok {
			return gojwt.MapClaims{
				identityKey: v.UserName,
			}
		}
		return gojwt.MapClaims{}
	}
}

func identityHandler() func(c *echo.Context) any {
	return func(c *echo.Context) any {
		claims := jwt.ExtractClaims(c)
		return &User{
			UserName: claims[identityKey].(string),
		}
	}
}

func authenticator() func(c *echo.Context) (any, error) {
	return func(c *echo.Context) (any, error) {
		var loginVals login
		if err := c.Bind(&loginVals); err != nil {
			return "", jwt.ErrMissingLoginValues
		}
		userID := loginVals.Username
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
	}
}

func authorizator() func(c *echo.Context, data any) bool {
	return func(c *echo.Context, data any) bool {
		if v, ok := data.(*User); ok && v.UserName == "admin" {
			return true
		}
		return false
	}
}

func unauthorized() func(c *echo.Context, code int, message string) {
	return func(c *echo.Context, code int, message string) {
		c.JSON(code, map[string]interface{}{
			"code":    code,
			"message": message,
		})
	}
}

func logoutResponse() func(c *echo.Context) {
	return func(c *echo.Context) {
		// This demonstrates that claims are now accessible during logout
		claims := jwt.ExtractClaims(c)
		user := c.Get(identityKey)

		response := map[string]interface{}{
			"code":    http.StatusOK,
			"message": "Successfully logged out",
		}

		// Show that we can access user information during logout
		if len(claims) > 0 {
			response["logged_out_user"] = claims[identityKey]
		}
		if user != nil {
			response["user_info"] = user.(*User).UserName
		}

		c.JSON(http.StatusOK, response)
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
