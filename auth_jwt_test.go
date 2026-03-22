package jwt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/LopanovCo/echo-jwt/core"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
	"github.com/tidwall/gjson"
)

// Login form structure.
type Login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

const (
	testAdmin      = "admin"
	testJWT        = "jwt"
	testUser       = "test"
	testPassword   = testAdmin
	testUserPasswd = testUser
)

var (
	key                  = []byte("secret key")
	defaultAuthenticator = func(c *echo.Context) (any, error) {
		var loginVals Login
		userID := loginVals.Username
		password := loginVals.Password

		if userID == testAdmin && password == testPassword {
			return userID, nil
		}

		return userID, ErrFailedAuthentication
	}
)

func makeTokenString(signingAlgorithm, username string) string {
	if signingAlgorithm == "" {
		signingAlgorithm = "HS256"
	}

	token := jwt.New(jwt.GetSigningMethod(signingAlgorithm))
	claims := token.Claims.(jwt.MapClaims)
	claims["identity"] = username
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	claims["orig_iat"] = time.Now().Unix()
	var tokenString string
	if signingAlgorithm == "RS256" {
		keyData, _ := os.ReadFile("testdata/jwtRS256.key")
		signKey, _ := jwt.ParseRSAPrivateKeyFromPEM(keyData)
		tokenString, _ = token.SignedString(signKey)
	} else {
		tokenString, _ = token.SignedString(key)
	}

	return tokenString
}

func keyFunc(token *jwt.Token) (any, error) {
	cert, err := os.ReadFile("testdata/jwtRS256.key.pub")
	if err != nil {
		return nil, err
	}
	return jwt.ParseRSAPublicKeyFromPEM(cert)
}

// Helper to perform JSON POST request
func performRequest(handler http.Handler, method, path string, body string, headers map[string]string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func TestMissingKey(t *testing.T) {
	_, err := New(&EchoJWTMiddleware{
		Realm:         "test zone",
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
	})

	assert.Error(t, err)
	assert.Equal(t, ErrMissingSecretKey, err)
}

func TestMissingPrivKey(t *testing.T) {
	_, err := New(&EchoJWTMiddleware{
		Realm:            "zone",
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "nonexisting",
	})

	assert.Error(t, err)
	assert.Equal(t, ErrNoPrivKeyFile, err)
}

func TestMissingPubKey(t *testing.T) {
	_, err := New(&EchoJWTMiddleware{
		Realm:            "zone",
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "testdata/jwtRS256.key",
		PubKeyFile:       "nonexisting",
	})

	assert.Error(t, err)
	assert.Equal(t, ErrNoPubKeyFile, err)
}

func TestInvalidPrivKey(t *testing.T) {
	_, err := New(&EchoJWTMiddleware{
		Realm:            "zone",
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "testdata/invalidprivkey.key",
		PubKeyFile:       "testdata/jwtRS256.key.pub",
	})

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidPrivKey, err)
}

func TestInvalidPrivKeyBytes(t *testing.T) {
	_, err := New(&EchoJWTMiddleware{
		Realm:            "zone",
		SigningAlgorithm: "RS256",
		PrivKeyBytes:     []byte("Invalid_Private_Key"),
		PubKeyFile:       "testdata/jwtRS256.key.pub",
	})

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidPrivKey, err)
}

func TestInvalidPubKey(t *testing.T) {
	_, err := New(&EchoJWTMiddleware{
		Realm:            "zone",
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "testdata/jwtRS256.key",
		PubKeyFile:       "testdata/invalidpubkey.key",
	})

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidPubKey, err)
}

func TestInvalidPubKeyBytes(t *testing.T) {
	_, err := New(&EchoJWTMiddleware{
		Realm:            "zone",
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "testdata/jwtRS256.key",
		PubKeyBytes:      []byte("Invalid_Private_Key"),
	})

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidPubKey, err)
}

func TestMissingTimeOut(t *testing.T) {
	authMiddleware, err := New(&EchoJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Authenticator: defaultAuthenticator,
	})

	assert.NoError(t, err)
	assert.Equal(t, time.Hour, authMiddleware.Timeout)
}

func TestMissingTokenLookup(t *testing.T) {
	authMiddleware, err := New(&EchoJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Authenticator: defaultAuthenticator,
	})

	assert.NoError(t, err)
	assert.Equal(t, "header:Authorization", authMiddleware.TokenLookup)
}

func helloHandler(c *echo.Context) error {
	return c.JSON(200, map[string]any{
		"text":  "Hello World.",
		"token": GetToken(c),
	})
}

// getRefreshTokenFromLogin performs a login and returns the refresh token from the response
func getRefreshTokenFromLogin(handler http.Handler) string {
	body := fmt.Sprintf(`{"username":"%s","password":"%s"}`, testAdmin, testAdmin)
	w := performRequest(handler, "POST", "/login", body, nil, nil)
	if w.Code == http.StatusOK {
		return gjson.Get(w.Body.String(), "refresh_token").String()
	}
	return ""
}

func echoHandler(auth *EchoJWTMiddleware) *echo.Echo {
	e := echo.New()


	e.POST("/login", auth.LoginHandler)
	e.POST("/logout", auth.LogoutHandler)
	e.POST("/refresh", auth.RefreshHandler)

	group := e.Group("/auth")
	// Refresh time can be longer than token timeout
	group.POST("/refresh_token", auth.RefreshHandler)
	group.Use(auth.MiddlewareFunc())
	group.GET("/hello", helloHandler)

	// Add back the param-based endpoint for testing
	e.GET("/g/:token/hello", helloHandler, auth.MiddlewareFunc())

	return e
}

func TestMissingAuthenticatorForLoginHandler(t *testing.T) {
	authMiddleware, err := New(&EchoJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
	})

	assert.NoError(t, err)

	handler := echoHandler(authMiddleware)

	w := performRequest(handler, "POST", "/login",
		fmt.Sprintf(`{"username":"%s","password":"%s"}`, testAdmin, testAdmin), nil, nil)

	message := gjson.Get(w.Body.String(), "message")
	assert.Equal(t, ErrMissingAuthenticatorFunc.Error(), message.String())
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestLoginHandler(t *testing.T) {
	// the middleware to test
	cookieName := testJWT
	cookieDomain := "example.com"
	authMiddleware, err := New(&EchoJWTMiddleware{
		Realm: "test zone",
		Key:   key,
		PayloadFunc: func(data any) jwt.MapClaims {
			// Set custom claim, to be checked in Authorizer method
			return jwt.MapClaims{"testkey": "testval", "exp": 0}
		},
		Authenticator: func(c *echo.Context) (any, error) {
			var loginVals Login
			if binderr := c.Bind(&loginVals); binderr != nil {
				return "", ErrMissingLoginValues
			}
			userID := loginVals.Username
			password := loginVals.Password
			if userID == testAdmin && password == testPassword {
				return userID, nil
			}
			return "", ErrFailedAuthentication
		},
		Authorizer: func(c *echo.Context, user any) bool {
			return true
		},
		LoginResponse: func(c *echo.Context, token *core.Token) {
			cookie, err := c.Cookie(testJWT)
			cookieVal := ""
			if err == nil {
				cookieVal = cookie.Value
			}

			expire := time.Unix(token.ExpiresAt, 0)
			c.JSON(http.StatusOK, map[string]any{
				"code":    http.StatusOK,
				"token":   token.AccessToken,
				"expire":  expire.Format(time.RFC3339),
				"message": "login successfully",
				"cookie":  cookieVal,
			})
		},
		SendCookie:   true,
		CookieName:   cookieName,
		CookieDomain: cookieDomain,
		TimeFunc:     func() time.Time { return time.Now().Add(time.Duration(5) * time.Minute) },
	})

	assert.NoError(t, err)

	handler := echoHandler(authMiddleware)

	// Test missing password
	// Note: Echo's Bind doesn't fail on missing fields (unlike Gin's ShouldBind with binding:"required"),
	// so the authenticator receives empty password and returns ErrFailedAuthentication
	w := performRequest(handler, "POST", "/login",
		fmt.Sprintf(`{"username":"%s"}`, testAdmin), nil, nil)
	message := gjson.Get(w.Body.String(), "message")
	assert.Equal(t, ErrFailedAuthentication.Error(), message.String())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")

	// Test wrong password
	w = performRequest(handler, "POST", "/login",
		fmt.Sprintf(`{"username":"%s","password":"test"}`, testAdmin), nil, nil)
	message = gjson.Get(w.Body.String(), "message")
	assert.Equal(t, ErrFailedAuthentication.Error(), message.String())
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Test correct credentials
	w = performRequest(handler, "POST", "/login",
		fmt.Sprintf(`{"username":"%s","password":"%s"}`, testAdmin, testAdmin), nil, nil)
	message = gjson.Get(w.Body.String(), "message")
	assert.Equal(t, "login successfully", message.String())
	assert.Equal(t, http.StatusOK, w.Code)
	setCookie := w.Header().Get("Set-Cookie")
	assert.True(t, strings.HasPrefix(setCookie, "jwt="))
	assert.True(t, strings.Contains(setCookie, "Domain=example.com"))
	assert.True(t, strings.Contains(setCookie, "Max-Age=3600"))
}

func TestParseToken(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
	})

	handler := echoHandler(authMiddleware)

	// Empty auth header
	w := performRequest(handler, "GET", "/auth/hello", "", map[string]string{"Authorization": ""}, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Invalid auth header
	w = performRequest(handler, "GET", "/auth/hello", "", map[string]string{"Authorization": "Test 1234"}, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Wrong algorithm
	w = performRequest(handler, "GET", "/auth/hello", "", map[string]string{
		"Authorization": "Bearer " + makeTokenString("HS384", testAdmin),
	}, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Valid token
	w = performRequest(handler, "GET", "/auth/hello", "", map[string]string{
		"Authorization": "Bearer " + makeTokenString("HS256", testAdmin),
	}, nil)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestParseTokenRS256(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:            "test zone",
		Key:              key,
		Timeout:          time.Hour,
		MaxRefresh:       time.Hour * 24,
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "testdata/jwtRS256.key",
		PubKeyFile:       "testdata/jwtRS256.key.pub",
		Authenticator:    defaultAuthenticator,
	})

	handler := echoHandler(authMiddleware)

	w := performRequest(handler, "GET", "/auth/hello", "", map[string]string{"Authorization": ""}, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	w = performRequest(handler, "GET", "/auth/hello", "", map[string]string{"Authorization": "Test 1234"}, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	w = performRequest(handler, "GET", "/auth/hello", "", map[string]string{
		"Authorization": "Bearer " + makeTokenString("HS384", testAdmin),
	}, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	w = performRequest(handler, "GET", "/auth/hello", "", map[string]string{
		"Authorization": "Bearer " + makeTokenString("RS256", testAdmin),
	}, nil)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestParseTokenKeyFunc(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:         "test zone",
		KeyFunc:       keyFunc,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
		Key:              []byte(""),
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "",
		PubKeyFile:       "",
	})

	handler := echoHandler(authMiddleware)

	w := performRequest(handler, "GET", "/auth/hello", "", map[string]string{"Authorization": ""}, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	w = performRequest(handler, "GET", "/auth/hello", "", map[string]string{"Authorization": "Test 1234"}, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	w = performRequest(handler, "GET", "/auth/hello", "", map[string]string{
		"Authorization": "Bearer " + makeTokenString("HS384", testAdmin),
	}, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	w = performRequest(handler, "GET", "/auth/hello", "", map[string]string{
		"Authorization": "Bearer " + makeTokenString("RS256", testAdmin),
	}, nil)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRefreshHandlerRS256(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:            "test zone",
		Key:              key,
		Timeout:          time.Hour,
		MaxRefresh:       time.Hour * 24,
		SigningAlgorithm: "RS256",
		PrivKeyFile:      "testdata/jwtRS256.key",
		PubKeyFile:       "testdata/jwtRS256.key.pub",
		SendCookie:       true,
		CookieName:       testJWT,
		Authenticator:    defaultAuthenticator,
		RefreshResponse: func(c *echo.Context, token *core.Token) {
			cookie, err := c.Cookie(testJWT)
			cookieVal := ""
			if err == nil {
				cookieVal = cookie.Value
			}

			expire := time.Unix(token.ExpiresAt, 0)
			c.JSON(http.StatusOK, map[string]any{
				"code":    http.StatusOK,
				"token":   token.AccessToken,
				"expire":  expire.Format(time.RFC3339),
				"message": "refresh successfully",
				"cookie":  cookieVal,
			})
		},
	})

	handler := echoHandler(authMiddleware)

	// Test missing refresh token
	w := performRequest(handler, "POST", "/auth/refresh_token", "", nil, nil)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Test invalid refresh token
	w = performRequest(handler, "POST", "/auth/refresh_token",
		`{"refresh_token":"invalid_token"}`, nil, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Test valid refresh token
	refreshToken := getRefreshTokenFromLogin(handler)
	if refreshToken != "" {
		w = performRequest(handler, "POST", "/auth/refresh_token",
			fmt.Sprintf(`{"refresh_token":"%s"}`, refreshToken), nil, nil)
		message := gjson.Get(w.Body.String(), "message")
		assert.Equal(t, "refresh successfully", message.String())
		assert.Equal(t, http.StatusOK, w.Code)
		accessToken := gjson.Get(w.Body.String(), "access_token")
		newRefreshToken := gjson.Get(w.Body.String(), "refresh_token")
		assert.NotEmpty(t, accessToken.String())
		assert.NotEmpty(t, newRefreshToken.String())
		assert.NotEqual(t, refreshToken, newRefreshToken.String())
	}
}

func TestRefreshHandler(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
	})

	handler := echoHandler(authMiddleware)

	// Test missing refresh token
	w := performRequest(handler, "POST", "/auth/refresh_token", "", nil, nil)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Test invalid refresh token
	w = performRequest(handler, "POST", "/auth/refresh_token",
		`{"refresh_token":"invalid_token"}`, nil, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Test valid refresh token
	refreshToken := getRefreshTokenFromLogin(handler)
	if refreshToken != "" {
		w = performRequest(handler, "POST", "/auth/refresh_token",
			fmt.Sprintf(`{"refresh_token":"%s"}`, refreshToken), nil, nil)
		assert.Equal(t, http.StatusOK, w.Code)
		accessToken := gjson.Get(w.Body.String(), "access_token")
		newRefreshToken := gjson.Get(w.Body.String(), "refresh_token")
		assert.NotEmpty(t, accessToken.String())
		assert.NotEmpty(t, newRefreshToken.String())
	}
}

func TestValidRefreshToken(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:               "test zone",
		Key:                 key,
		Timeout:             time.Hour,
		MaxRefresh:          2 * time.Hour,
		RefreshTokenTimeout: 24 * time.Hour,
		Authenticator:       defaultAuthenticator,
	})

	handler := echoHandler(authMiddleware)

	refreshToken := getRefreshTokenFromLogin(handler)
	if refreshToken != "" {
		w := performRequest(handler, "POST", "/auth/refresh_token",
			fmt.Sprintf(`{"refresh_token":"%s"}`, refreshToken), nil, nil)
		assert.Equal(t, http.StatusOK, w.Code)
	}
}

func TestExpiredTokenOnRefreshHandler(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:               "test zone",
		Key:                 key,
		Timeout:             time.Hour,
		RefreshTokenTimeout: time.Millisecond,
		Authenticator:       defaultAuthenticator,
	})

	handler := echoHandler(authMiddleware)

	refreshToken := getRefreshTokenFromLogin(handler)
	if refreshToken != "" {
		time.Sleep(2 * time.Millisecond)

		w := performRequest(handler, "POST", "/auth/refresh_token",
			fmt.Sprintf(`{"refresh_token":"%s"}`, refreshToken), nil, nil)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	}
}

func TestAuthorizer(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
		Authorizer: func(c *echo.Context, data any) bool {
			return data.(string) == testAdmin
		},
	})

	handler := echoHandler(authMiddleware)

	w := performRequest(handler, "GET", "/auth/hello", "", map[string]string{
		"Authorization": "Bearer " + makeTokenString("HS256", "test"),
	}, nil)
	assert.Equal(t, http.StatusForbidden, w.Code)

	w = performRequest(handler, "GET", "/auth/hello", "", map[string]string{
		"Authorization": "Bearer " + makeTokenString("HS256", testAdmin),
	}, nil)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestParseTokenWithJsonNumber(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(c *echo.Context, code int, message string) {
			c.String(code, message)
		},
		ParseOptions: []jwt.ParserOption{jwt.WithJSONNumber()},
	})

	handler := echoHandler(authMiddleware)

	w := performRequest(handler, "GET", "/auth/hello", "", map[string]string{
		"Authorization": "Bearer " + makeTokenString("HS256", testAdmin),
	}, nil)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestClaimsDuringAuthorization(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		PayloadFunc: func(data any) jwt.MapClaims {
			if v, ok := data.(jwt.MapClaims); ok {
				return v
			}

			if reflect.TypeOf(data).String() != "string" {
				return jwt.MapClaims{}
			}

			var testkey string
			switch data.(string) {
			case testAdmin:
				testkey = "1234"
			case testUser:
				testkey = "5678"
			case "Guest":
				testkey = ""
			}
			now := time.Now()
			return jwt.MapClaims{
				"identity": data.(string),
				"testkey":  testkey,
				"exp":      now.Add(time.Hour).Unix(),
				"iat":      now.Unix(),
				"nbf":      now.Unix(),
			}
		},
		Authenticator: func(c *echo.Context) (any, error) {
			var loginVals Login
			if err := json.NewDecoder(c.Request().Body).Decode(&loginVals); err != nil {
				return "", ErrMissingLoginValues
			}
			userID := loginVals.Username
			password := loginVals.Password
			if userID == testAdmin && password == testPassword {
				return userID, nil
			}
			if userID == testUser && password == testUserPasswd {
				return userID, nil
			}
			return "Guest", ErrFailedAuthentication
		},
		Authorizer: func(c *echo.Context, user any) bool {
			jwtClaims := ExtractClaims(c)
			if jwtClaims["identity"] == "administrator" {
				return true
			}
			if jwtClaims["testkey"] == "1234" && jwtClaims["identity"] == testAdmin {
				return true
			}
			if jwtClaims["testkey"] == "5678" && jwtClaims["identity"] == testUser {
				return true
			}
			return false
		},
	})

	handler := echoHandler(authMiddleware)

	userToken, _, _ := authMiddleware.generateAccessToken(jwt.MapClaims{
		"identity": "administrator",
	})

	w := performRequest(handler, "GET", "/auth/hello", "", map[string]string{
		"Authorization": "Bearer " + userToken,
	}, nil)
	assert.Equal(t, http.StatusOK, w.Code)

	w = performRequest(handler, "POST", "/login",
		fmt.Sprintf(`{"username":"%s","password":"%s"}`, testAdmin, testAdmin), nil, nil)
	userToken = gjson.Get(w.Body.String(), "access_token").String()
	assert.Equal(t, http.StatusOK, w.Code)

	w = performRequest(handler, "GET", "/auth/hello", "", map[string]string{
		"Authorization": "Bearer " + userToken,
	}, nil)
	assert.Equal(t, http.StatusOK, w.Code)

	w = performRequest(handler, "POST", "/login",
		fmt.Sprintf(`{"username":"%s","password":"%s"}`, testUser, testUser), nil, nil)
	userToken = gjson.Get(w.Body.String(), "access_token").String()
	assert.Equal(t, http.StatusOK, w.Code)

	w = performRequest(handler, "GET", "/auth/hello", "", map[string]string{
		"Authorization": "Bearer " + userToken,
	}, nil)
	assert.Equal(t, http.StatusOK, w.Code)
}

func ConvertClaims(claims jwt.MapClaims) map[string]any {
	return map[string]any{}
}

func TestEmptyClaims(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		Authenticator: func(c *echo.Context) (any, error) {
			var loginVals Login
			userID := loginVals.Username
			password := loginVals.Password
			if userID == testAdmin && password == testPassword {
				return "", nil
			}
			if userID == testUser && password == testUserPasswd {
				return "Administrator", nil
			}
			return userID, ErrFailedAuthentication
		},
		Unauthorized: func(c *echo.Context, code int, message string) {
			assert.Empty(t, ExtractClaims(c))
			assert.Empty(t, ConvertClaims(ExtractClaims(c)))
			c.String(code, message)
		},
	})

	handler := echoHandler(authMiddleware)

	w := performRequest(handler, "GET", "/auth/hello", "", map[string]string{
		"Authorization": "Bearer 1234",
	}, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	assert.Empty(t, jwt.MapClaims{})
}

func TestUnauthorized(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(c *echo.Context, code int, message string) {
			c.String(code, message)
		},
	})

	handler := echoHandler(authMiddleware)

	w := performRequest(handler, "GET", "/auth/hello", "", map[string]string{
		"Authorization": "Bearer 1234",
	}, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestTokenExpire(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    -time.Second,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(c *echo.Context, code int, message string) {
			c.String(code, message)
		},
	})

	handler := echoHandler(authMiddleware)

	w := performRequest(handler, "POST", "/auth/refresh_token", "", nil, nil)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTokenFromQueryString(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(c *echo.Context, code int, message string) {
			c.String(code, message)
		},
		TokenLookup: "query:token",
	})

	handler := echoHandler(authMiddleware)

	userToken, _, _ := authMiddleware.generateAccessToken(jwt.MapClaims{
		"identity": testAdmin,
	})

	// Header should not work when looking from query
	w := performRequest(handler, "GET", "/auth/hello", "", map[string]string{
		"Authorization": "Bearer " + userToken,
	}, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Query should work
	w = performRequest(handler, "GET", "/auth/hello?token="+userToken, "", map[string]string{
		"Authorization": "Bearer " + userToken,
	}, nil)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTokenFromParamPath(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(c *echo.Context, code int, message string) {
			c.String(code, message)
		},
		TokenLookup: "param:token",
	})

	handler := echoHandler(authMiddleware)

	userToken, _, _ := authMiddleware.generateAccessToken(jwt.MapClaims{
		"identity": testAdmin,
	})

	w := performRequest(handler, "GET", "/auth/hello", "", map[string]string{
		"Authorization": "Bearer " + userToken,
	}, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	w = performRequest(handler, "GET", "/g/"+userToken+"/hello", "", nil, nil)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTokenFromCookieString(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(c *echo.Context, code int, message string) {
			c.String(code, message)
		},
		TokenLookup: "cookie:token",
	})

	handler := echoHandler(authMiddleware)

	userToken, _, _ := authMiddleware.generateAccessToken(jwt.MapClaims{
		"identity": testAdmin,
	})

	// Header should not work
	w := performRequest(handler, "GET", "/auth/hello", "", map[string]string{
		"Authorization": "Bearer " + userToken,
	}, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Cookie should work
	w = performRequest(handler, "GET", "/auth/hello", "", nil, []*http.Cookie{
		{Name: "token", Value: userToken},
	})
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify token is available in response
	w = performRequest(handler, "GET", "/auth/hello", "", nil, []*http.Cookie{
		{Name: "token", Value: userToken},
	})
	tokenVal := gjson.Get(w.Body.String(), "token")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, userToken, tokenVal.String())
}

func TestDefineTokenHeadName(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		TokenHeadName: "JWTTOKEN       ",
		Authenticator: defaultAuthenticator,
	})

	handler := echoHandler(authMiddleware)

	w := performRequest(handler, "GET", "/auth/hello", "", map[string]string{
		"Authorization": "Bearer " + makeTokenString("HS256", testAdmin),
	}, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	w = performRequest(handler, "GET", "/auth/hello", "", map[string]string{
		"Authorization": "JWTTOKEN " + makeTokenString("HS256", "admin"),
	}, nil)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHTTPStatusMessageFunc(t *testing.T) {
	successError := errors.New("Successful test error")
	failedError := errors.New("Failed test error")
	successMessage := "Overwrite error message."

	authMiddleware, _ := New(&EchoJWTMiddleware{
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
		HTTPStatusMessageFunc: func(c *echo.Context, e error) string {
			if e == successError {
				return successMessage
			}
			return e.Error()
		},
	})

	successString := authMiddleware.HTTPStatusMessageFunc(nil, successError)
	failedString := authMiddleware.HTTPStatusMessageFunc(nil, failedError)

	assert.Equal(t, successMessage, successString)
	assert.NotEqual(t, successMessage, failedString)
}

func TestSendAuthorizationBool(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:             "test zone",
		Key:               key,
		Timeout:           time.Hour,
		MaxRefresh:        time.Hour * 24,
		Authenticator:     defaultAuthenticator,
		SendAuthorization: true,
		Authorizer: func(c *echo.Context, data any) bool {
			return data.(string) == testAdmin
		},
	})

	handler := echoHandler(authMiddleware)

	w := performRequest(handler, "GET", "/auth/hello", "", map[string]string{
		"Authorization": "Bearer " + makeTokenString("HS256", "test"),
	}, nil)
	assert.Equal(t, http.StatusForbidden, w.Code)

	w = performRequest(handler, "GET", "/auth/hello", "", map[string]string{
		"Authorization": "Bearer " + makeTokenString("HS256", testAdmin),
	}, nil)
	token := w.Header().Get("Authorization")
	assert.Equal(t, "Bearer "+makeTokenString("HS256", testAdmin), token)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestExpiredTokenOnAuth(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:             "test zone",
		Key:               key,
		Timeout:           time.Hour,
		MaxRefresh:        time.Hour * 24,
		Authenticator:     defaultAuthenticator,
		SendAuthorization: true,
		Authorizer: func(c *echo.Context, data any) bool {
			return data.(string) == testAdmin
		},
		TimeFunc: func() time.Time {
			return time.Now().AddDate(0, 0, 1)
		},
	})

	handler := echoHandler(authMiddleware)

	w := performRequest(handler, "GET", "/auth/hello", "", map[string]string{
		"Authorization": "Bearer " + makeTokenString("HS256", testAdmin),
	}, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestBadTokenOnRefreshHandler(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
	})

	handler := echoHandler(authMiddleware)

	w := performRequest(handler, "POST", "/auth/refresh_token",
		`{"refresh_token":"BadToken"}`, nil, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestExpiredField(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
	})

	handler := echoHandler(authMiddleware)

	token := jwt.New(jwt.GetSigningMethod("HS256"))
	claims := token.Claims.(jwt.MapClaims)
	claims["identity"] = testAdmin
	claims["orig_iat"] = 0
	tokenString, _ := token.SignedString(key)

	w := performRequest(handler, "GET", "/auth/hello", "", map[string]string{
		"Authorization": "Bearer " + tokenString,
	}, nil)
	message := gjson.Get(w.Body.String(), "message")
	assert.Equal(t, ErrMissingExpField.Error(), message.String())
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// wrong format
	claims["exp"] = "wrongFormatForExpiry"
	tokenString, _ = token.SignedString(key)

	w = performRequest(handler, "GET", "/auth/hello", "", map[string]string{
		"Authorization": "Bearer " + tokenString,
	}, nil)
	message = gjson.Get(w.Body.String(), "message")
	assert.Equal(t, ErrWrongFormatOfExp.Error(), strings.ToLower(message.String()))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestExpiredFieldRequiredParserOption(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
		ParseOptions:  []jwt.ParserOption{jwt.WithExpirationRequired()},
	})

	handler := echoHandler(authMiddleware)

	token := jwt.New(jwt.GetSigningMethod("HS256"))
	claims := token.Claims.(jwt.MapClaims)
	claims["identity"] = testAdmin
	claims["orig_iat"] = 0
	tokenString, _ := token.SignedString(key)

	w := performRequest(handler, "GET", "/auth/hello", "", map[string]string{
		"Authorization": "Bearer " + tokenString,
	}, nil)
	message := gjson.Get(w.Body.String(), "message")
	assert.Equal(t, ErrMissingExpField.Error(), message.String())
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// wrong format
	claims["exp"] = "wrongFormatForExpiry"
	tokenString, _ = token.SignedString(key)

	w = performRequest(handler, "GET", "/auth/hello", "", map[string]string{
		"Authorization": "Bearer " + tokenString,
	}, nil)
	message = gjson.Get(w.Body.String(), "message")
	assert.Equal(t, ErrWrongFormatOfExp.Error(), strings.ToLower(message.String()))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCheckTokenString(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       1 * time.Second,
		Authenticator: defaultAuthenticator,
		Unauthorized: func(c *echo.Context, code int, message string) {
			c.String(code, message)
		},
		PayloadFunc: func(data any) jwt.MapClaims {
			if v, ok := data.(jwt.MapClaims); ok {
				return v
			}
			return nil
		},
	})

	handler := echoHandler(authMiddleware)

	userToken, _, _ := authMiddleware.generateAccessToken(jwt.MapClaims{
		"identity": testAdmin,
	})

	w := performRequest(handler, "GET", "/auth/hello", "", map[string]string{
		"Authorization": "Bearer " + userToken,
	}, nil)
	assert.Equal(t, http.StatusOK, w.Code)

	parsedToken, err := authMiddleware.ParseTokenString(userToken)
	assert.NoError(t, err)
	tokenClaims := ExtractClaimsFromToken(parsedToken)
	assert.Equal(t, testAdmin, tokenClaims["identity"])

	time.Sleep(2 * time.Second)

	w = performRequest(handler, "GET", "/auth/hello", "", map[string]string{
		"Authorization": "Bearer " + userToken,
	}, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	_, err = authMiddleware.ParseTokenString(userToken)
	assert.Error(t, err)
	assert.Equal(t, jwt.MapClaims{}, ExtractClaimsFromToken(nil))
}

func TestLogout(t *testing.T) {
	cookieName := testJWT
	cookieDomain := "example.com"
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:         "test zone",
		Key:           key,
		Timeout:       time.Hour,
		Authenticator: defaultAuthenticator,
		SendCookie:    true,
		CookieName:    cookieName,
		CookieDomain:  cookieDomain,
	})

	handler := echoHandler(authMiddleware)

	w := performRequest(handler, "POST", "/logout", "", nil, nil)
	assert.Equal(t, http.StatusOK, w.Code)
	setCookie := w.Header().Get("Set-Cookie")
	assert.Contains(t, setCookie, fmt.Sprintf("%s=", cookieName))
	assert.Contains(t, setCookie, fmt.Sprintf("Domain=%s", cookieDomain))
	assert.Contains(t, setCookie, "Max-Age=0")
}

func TestSetCookie(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	c := e.NewContext(req, w)

	mw, _ := New(&EchoJWTMiddleware{
		Realm:          "test zone",
		Key:            key,
		Timeout:        time.Hour,
		Authenticator:  defaultAuthenticator,
		SendCookie:     true,
		CookieName:     testJWT,
		CookieMaxAge:   time.Hour,
		CookieDomain:   "example.com",
		SecureCookie:   false,
		CookieHTTPOnly: true,
		TimeFunc:       time.Now,
	})

	token := makeTokenString("HS384", testAdmin)
	mw.SetCookie(c, token)

	cookies := w.Result().Cookies()
	assert.Len(t, cookies, 1)

	cookie := cookies[0]
	assert.Equal(t, testJWT, cookie.Name)
	assert.Equal(t, token, cookie.Value)
	assert.Equal(t, "/", cookie.Path)
	assert.Equal(t, "example.com", cookie.Domain)
	assert.Equal(t, true, cookie.HttpOnly)
}

func TestTokenGenerator(t *testing.T) {
	authMiddleware, err := New(&EchoJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		Authenticator: func(c *echo.Context) (any, error) {
			return testAdmin, nil
		},
		PayloadFunc: func(data any) jwt.MapClaims {
			return jwt.MapClaims{
				"identity": data,
			}
		},
		Authorizer: func(c *echo.Context, data any) bool {
			return data == testAdmin
		},
		Unauthorized: func(c *echo.Context, code int, message string) {
			c.JSON(code, map[string]any{
				"code":    code,
				"message": message,
			})
		},
	})

	assert.NoError(t, err)

	userData := testAdmin
	ctx := context.Background()
	tokenPair, err := authMiddleware.TokenGenerator(ctx, userData)

	assert.NoError(t, err)
	assert.NotNil(t, tokenPair)
	assert.NotEmpty(t, tokenPair.AccessToken)
	assert.NotEmpty(t, tokenPair.RefreshToken)
	assert.Equal(t, "Bearer", tokenPair.TokenType)
	assert.True(t, tokenPair.ExpiresAt > time.Now().Unix())
	assert.True(t, tokenPair.CreatedAt <= time.Now().Unix())
	assert.True(t, tokenPair.ExpiresIn() > 0)

	parsedToken, err := authMiddleware.ParseTokenString(tokenPair.AccessToken)
	assert.NoError(t, err)
	assert.True(t, parsedToken.Valid)

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	assert.True(t, ok)
	assert.Equal(t, userData, claims["identity"])
}

func TestTokenGeneratorWithRevocation(t *testing.T) {
	authMiddleware, err := New(&EchoJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		Authenticator: func(c *echo.Context) (any, error) {
			return testAdmin, nil
		},
		PayloadFunc: func(data any) jwt.MapClaims {
			return jwt.MapClaims{
				"identity": data,
			}
		},
	})

	assert.NoError(t, err)

	userData := testAdmin
	ctx := context.Background()

	oldTokenPair, err := authMiddleware.TokenGenerator(ctx, userData)
	assert.NoError(t, err)

	storedData, err := authMiddleware.validateRefreshToken(ctx, oldTokenPair.RefreshToken)
	assert.NoError(t, err)
	assert.Equal(t, userData, storedData)

	newTokenPair, err := authMiddleware.TokenGeneratorWithRevocation(ctx, userData, oldTokenPair.RefreshToken)
	assert.NoError(t, err)
	assert.NotNil(t, newTokenPair)

	assert.NotEqual(t, oldTokenPair.RefreshToken, newTokenPair.RefreshToken)

	_, err = authMiddleware.validateRefreshToken(ctx, oldTokenPair.RefreshToken)
	assert.Error(t, err)

	storedData, err = authMiddleware.validateRefreshToken(ctx, newTokenPair.RefreshToken)
	assert.NoError(t, err)
	assert.Equal(t, userData, storedData)

	anotherTokenPair, err := authMiddleware.TokenGeneratorWithRevocation(ctx, userData, oldTokenPair.RefreshToken)
	assert.NoError(t, err)
	assert.NotNil(t, anotherTokenPair)

	finalTokenPair, err := authMiddleware.TokenGeneratorWithRevocation(ctx, userData, "non_existent_token")
	assert.NoError(t, err)
	assert.NotNil(t, finalTokenPair)
}

func TestTokenStruct(t *testing.T) {
	authMiddleware, err := New(&EchoJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		Authenticator: func(c *echo.Context) (any, error) {
			return testAdmin, nil
		},
	})

	assert.NoError(t, err)

	userData := testAdmin
	ctx := context.Background()
	tokenPair, err := authMiddleware.TokenGenerator(ctx, userData)
	assert.NoError(t, err)

	expiresIn := tokenPair.ExpiresIn()
	assert.True(t, expiresIn > 3500)
	assert.True(t, expiresIn <= 3600)

	assert.NotEmpty(t, tokenPair.AccessToken)
	assert.Equal(t, "Bearer", tokenPair.TokenType)
	assert.NotEmpty(t, tokenPair.RefreshToken)
	assert.True(t, tokenPair.ExpiresAt > time.Now().Unix())
	assert.True(t, tokenPair.CreatedAt > 0)
	assert.True(t, tokenPair.CreatedAt <= time.Now().Unix())
}

func TestWWWAuthenticateHeader(t *testing.T) {
	testCases := []struct {
		name           string
		realm          string
		expectedHeader string
		setupRequest   func(req *http.Request)
	}{
		{
			name:           "default realm with invalid token",
			realm:          "test zone",
			expectedHeader: `Bearer realm="test zone"`,
			setupRequest: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer invalid_token")
			},
		},
		{
			name:           "custom realm with empty auth header",
			realm:          "my custom realm",
			expectedHeader: `Bearer realm="my custom realm"`,
			setupRequest:   func(req *http.Request) {},
		},
		{
			name:           "realm with special characters",
			realm:          `test-zone_123`,
			expectedHeader: `Bearer realm="test-zone_123"`,
			setupRequest: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer invalid")
			},
		},
		{
			name:           "expired token",
			realm:          "test zone",
			expectedHeader: `Bearer realm="test zone"`,
			setupRequest: func(req *http.Request) {
				token := jwt.New(jwt.GetSigningMethod("HS256"))
				claims := token.Claims.(jwt.MapClaims)
				claims["identity"] = testAdmin
				claims["exp"] = time.Now().Add(-time.Hour).Unix()
				claims["orig_iat"] = time.Now().Add(-2 * time.Hour).Unix()
				tokenString, _ := token.SignedString(key)
				req.Header.Set("Authorization", "Bearer "+tokenString)
			},
		},
		{
			name:           "malformed token",
			realm:          "api realm",
			expectedHeader: `Bearer realm="api realm"`,
			setupRequest: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer not.a.valid.jwt.token")
			},
		},
		{
			name:           "missing Bearer prefix",
			realm:          "test zone",
			expectedHeader: `Bearer realm="test zone"`,
			setupRequest: func(req *http.Request) {
				req.Header.Set("Authorization", "invalid_token_without_bearer")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			authMiddleware, err := New(&EchoJWTMiddleware{
				Realm:         tc.realm,
				Key:           key,
				Timeout:       time.Hour,
				MaxRefresh:    time.Hour * 24,
				Authenticator: defaultAuthenticator,
			})
			assert.NoError(t, err)

			handler := echoHandler(authMiddleware)

			req := httptest.NewRequest("GET", "/auth/hello", nil)
			if tc.setupRequest != nil {
				tc.setupRequest(req)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			assert.Equal(t, http.StatusUnauthorized, w.Code)
			assert.Equal(t, tc.expectedHeader, w.Header().Get("WWW-Authenticate"))
		})
	}
}

func TestWWWAuthenticateHeaderOnRefresh(t *testing.T) {
	authMiddleware, err := New(&EchoJWTMiddleware{
		Realm:         "refresh realm",
		Key:           key,
		Timeout:       time.Hour,
		MaxRefresh:    time.Hour * 24,
		Authenticator: defaultAuthenticator,
	})
	assert.NoError(t, err)

	handler := echoHandler(authMiddleware)

	w := performRequest(handler, "POST", "/auth/refresh_token",
		`{"refresh_token":"invalid_refresh_token"}`, nil, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, `Bearer realm="refresh realm"`, w.Header().Get("WWW-Authenticate"))
}

func TestWWWAuthenticateHeaderNotSetOnSuccess(t *testing.T) {
	authMiddleware, err := New(&EchoJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		Authenticator: func(c *echo.Context) (any, error) {
			var loginVals Login
			if err := c.Bind(&loginVals); err != nil {
				return "", ErrMissingLoginValues
			}
			if loginVals.Username == testAdmin && loginVals.Password == testPassword {
				return loginVals.Username, nil
			}
			return "", ErrFailedAuthentication
		},
	})
	assert.NoError(t, err)

	handler := echoHandler(authMiddleware)

	w := performRequest(handler, "POST", "/login",
		fmt.Sprintf(`{"username":"%s","password":"%s"}`, testAdmin, testAdmin), nil, nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("WWW-Authenticate"))

	token := makeTokenString("HS256", testAdmin)

	w = performRequest(handler, "GET", "/auth/hello", "", map[string]string{
		"Authorization": "Bearer " + token,
	}, nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("WWW-Authenticate"))
}

func TestWWWAuthenticateHeaderWithDifferentRealms(t *testing.T) {
	realms := []string{
		"echo jwt",   // default
		"API Server", // with space
		"my-api",     // with dash
		"realm_test", // with underscore
		"MyApp v1.0", // with version
		"",           // empty (should use default)
	}

	for _, realm := range realms {
		t.Run(fmt.Sprintf("realm=%q", realm), func(t *testing.T) {
			authMiddleware, err := New(&EchoJWTMiddleware{
				Realm:         realm,
				Key:           key,
				Timeout:       time.Hour,
				MaxRefresh:    time.Hour * 24,
				Authenticator: defaultAuthenticator,
			})
			assert.NoError(t, err)

			handler := echoHandler(authMiddleware)

			expectedRealm := realm
			if expectedRealm == "" {
				expectedRealm = "echo jwt" // default realm
			}

			w := performRequest(handler, "GET", "/auth/hello", "", map[string]string{
				"Authorization": "Bearer invalid",
			}, nil)
			assert.Equal(t, http.StatusUnauthorized, w.Code)
			assert.Equal(t, fmt.Sprintf(`Bearer realm="%s"`, expectedRealm), w.Header().Get("WWW-Authenticate"))
		})
	}
}

func TestStandardJWTClaimsInPayloadFunc(t *testing.T) {
	authMiddleware, err := New(&EchoJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		Authenticator: func(c *echo.Context) (any, error) {
			return "user123", nil
		},
		PayloadFunc: func(data any) jwt.MapClaims {
			userID := data.(string)
			now := time.Now()
			return jwt.MapClaims{
				"sub": userID,
				"iss": "my-app",
				"aud": "my-api",
				"nbf": now.Unix(),
				"iat": now.Unix(),
				"jti": "unique-token-id-12345",
				"exp": now.Add(time.Hour * 2).Unix(),
				"identity": userID,
				"role":     "admin",
			}
		},
	})

	assert.NoError(t, err)

	ctx := context.Background()
	tokenPair, err := authMiddleware.TokenGenerator(ctx, "user123")
	assert.NoError(t, err)
	assert.NotNil(t, tokenPair)

	parsedToken, err := authMiddleware.ParseTokenString(tokenPair.AccessToken)
	assert.NoError(t, err)
	assert.True(t, parsedToken.Valid)

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	assert.True(t, ok)

	assert.Equal(t, "user123", claims["sub"])
	assert.Equal(t, "my-app", claims["iss"])
	assert.Equal(t, "my-api", claims["aud"])
	assert.NotNil(t, claims["nbf"])
	assert.NotNil(t, claims["iat"])
	assert.Equal(t, "unique-token-id-12345", claims["jti"])
	assert.Equal(t, "user123", claims["identity"])
	assert.Equal(t, "admin", claims["role"])
	assert.NotNil(t, claims["exp"])
	assert.NotNil(t, claims["orig_iat"])
}

func TestFrameworkClaimsCannotBeOverwritten(t *testing.T) {
	fixedTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	authMiddleware, err := New(&EchoJWTMiddleware{
		Realm:      "test zone",
		Key:        key,
		Timeout:    time.Hour,
		MaxRefresh: time.Hour * 24,
		TimeFunc:   func() time.Time { return fixedTime },
		Authenticator: func(c *echo.Context) (any, error) {
			return "user123", nil
		},
		PayloadFunc: func(data any) jwt.MapClaims {
			return jwt.MapClaims{
				"exp":      int64(9999999999),
				"orig_iat": int64(1111111111),
				"identity": data.(string),
			}
		},
	})

	assert.NoError(t, err)

	ctx := context.Background()
	tokenPair, err := authMiddleware.TokenGenerator(ctx, "user123")
	assert.NoError(t, err)

	parsedToken, err := authMiddleware.ParseTokenString(tokenPair.AccessToken)
	assert.NoError(t, err)

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	assert.True(t, ok)

	expValue, ok := claims["exp"].(float64)
	assert.True(t, ok)
	expectedExp := fixedTime.Add(time.Hour).Unix()
	assert.Equal(t, expectedExp, int64(expValue))

	origIatValue, ok := claims["orig_iat"].(float64)
	assert.True(t, ok)
	assert.Equal(t, fixedTime.Unix(), int64(origIatValue))

	assert.Equal(t, "user123", claims["identity"])
}

func TestAllStandardClaimsCanBeSet(t *testing.T) {
	testCases := []struct {
		name       string
		claimKey   string
		claimValue any
	}{
		{"sub (Subject)", "sub", "user-12345"},
		{"iss (Issuer)", "iss", "https://auth.example.com"},
		{"aud (Audience)", "aud", "https://api.example.com"},
		{"nbf (Not Before)", "nbf", time.Now().Unix()},
		{"iat (Issued At)", "iat", time.Now().Unix()},
		{"jti (JWT ID)", "jti", "550e8400-e29b-41d4-a716-446655440000"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			authMiddleware, err := New(&EchoJWTMiddleware{
				Realm:   "test zone",
				Key:     key,
				Timeout: time.Hour,
				Authenticator: func(c *echo.Context) (any, error) {
					return "user", nil
				},
				PayloadFunc: func(data any) jwt.MapClaims {
					return jwt.MapClaims{
						tc.claimKey: tc.claimValue,
						"identity":  data,
					}
				},
			})
			assert.NoError(t, err)

			ctx := context.Background()
			tokenPair, err := authMiddleware.TokenGenerator(ctx, "user")
			assert.NoError(t, err)

			parsedToken, err := authMiddleware.ParseTokenString(tokenPair.AccessToken)
			assert.NoError(t, err)

			claims, ok := parsedToken.Claims.(jwt.MapClaims)
			assert.True(t, ok)

			switch expected := tc.claimValue.(type) {
			case int64:
				actual, ok := claims[tc.claimKey].(float64)
				assert.True(t, ok, "claim %s should be a number", tc.claimKey)
				assert.Equal(t, float64(expected), actual, "claim %s should match", tc.claimKey)
			default:
				assert.Equal(t, tc.claimValue, claims[tc.claimKey], "claim %s should be set correctly", tc.claimKey)
			}
		})
	}
}

func TestSubClaimAsUserIdentifier(t *testing.T) {
	authMiddleware, err := New(&EchoJWTMiddleware{
		Realm:       "test zone",
		Key:         key,
		Timeout:     time.Hour,
		IdentityKey: "sub",
		Authenticator: func(c *echo.Context) (any, error) {
			var loginVals Login
			if err := c.Bind(&loginVals); err != nil {
				return "", ErrMissingLoginValues
			}
			return loginVals.Username, nil
		},
		PayloadFunc: func(data any) jwt.MapClaims {
			userID := data.(string)
			return jwt.MapClaims{
				"sub":   userID,
				"name":  "Test User",
				"email": "test@example.com",
			}
		},
		IdentityHandler: func(c *echo.Context) any {
			claims := ExtractClaims(c)
			return claims["sub"]
		},
		Authorizer: func(c *echo.Context, data any) bool {
			userID, ok := data.(string)
			if !ok {
				return false
			}
			return userID == testAdmin
		},
	})
	assert.NoError(t, err)

	handler := echoHandler(authMiddleware)

	// Login and get token
	w := performRequest(handler, "POST", "/login",
		fmt.Sprintf(`{"username":"%s","password":"%s"}`, testAdmin, testAdmin), nil, nil)
	assert.Equal(t, http.StatusOK, w.Code)
	accessToken := gjson.Get(w.Body.String(), "access_token").String()
	assert.NotEmpty(t, accessToken)

	// Use token
	w = performRequest(handler, "GET", "/auth/hello", "", map[string]string{
		"Authorization": "Bearer " + accessToken,
	}, nil)
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify claims
	parsedToken, err := authMiddleware.ParseTokenString(accessToken)
	assert.NoError(t, err)
	claims := ExtractClaimsFromToken(parsedToken)
	assert.Equal(t, testAdmin, claims["sub"])
	assert.Equal(t, "Test User", claims["name"])
	assert.Equal(t, "test@example.com", claims["email"])
}

func TestLeewayForClockSkew(t *testing.T) {
	fixedTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	t.Run("WithoutLeeway_RejectsExpiredToken", func(t *testing.T) {
		authMiddleware, _ := New(&EchoJWTMiddleware{
			Realm:         "test zone",
			Key:           key,
			Timeout:       time.Hour,
			Authenticator: defaultAuthenticator,
			TimeFunc: func() time.Time {
				return fixedTime.Add(time.Hour + 45*time.Second)
			},
		})

		handler := echoHandler(authMiddleware)

		token := jwt.New(jwt.GetSigningMethod("HS256"))
		claims := token.Claims.(jwt.MapClaims)
		claims["identity"] = testAdmin
		claims["exp"] = fixedTime.Add(time.Hour).Unix()
		claims["orig_iat"] = fixedTime.Unix()
		tokenString, _ := token.SignedString(key)

		w := performRequest(handler, "GET", "/auth/hello", "", map[string]string{
			"Authorization": "Bearer " + tokenString,
		}, nil)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("WithLeeway_AcceptsRecentlyExpiredToken", func(t *testing.T) {
		authMiddleware, _ := New(&EchoJWTMiddleware{
			Realm:         "test zone",
			Key:           key,
			Timeout:       time.Hour,
			Authenticator: defaultAuthenticator,
			ParseOptions: []jwt.ParserOption{
				jwt.WithLeeway(60 * time.Second),
			},
			TimeFunc: func() time.Time {
				return fixedTime.Add(time.Hour + 45*time.Second)
			},
		})

		handler := echoHandler(authMiddleware)

		token := jwt.New(jwt.GetSigningMethod("HS256"))
		claims := token.Claims.(jwt.MapClaims)
		claims["identity"] = testAdmin
		claims["exp"] = fixedTime.Add(time.Hour).Unix()
		claims["orig_iat"] = fixedTime.Unix()
		tokenString, _ := token.SignedString(key)

		w := performRequest(handler, "GET", "/auth/hello", "", map[string]string{
			"Authorization": "Bearer " + tokenString,
		}, nil)
		assert.Equal(t, http.StatusOK, w.Code)
		data := gjson.Get(w.Body.String(), "text")
		assert.Equal(t, "Hello World.", data.String())
	})

	t.Run("WithLeeway_RejectsTokenBeyondLeewayWindow", func(t *testing.T) {
		authMiddleware, _ := New(&EchoJWTMiddleware{
			Realm:         "test zone",
			Key:           key,
			Timeout:       time.Hour,
			Authenticator: defaultAuthenticator,
			ParseOptions: []jwt.ParserOption{
				jwt.WithLeeway(60 * time.Second),
			},
			TimeFunc: func() time.Time {
				return fixedTime.Add(time.Hour + 90*time.Second)
			},
		})

		handler := echoHandler(authMiddleware)

		token := jwt.New(jwt.GetSigningMethod("HS256"))
		claims := token.Claims.(jwt.MapClaims)
		claims["identity"] = testAdmin
		claims["exp"] = fixedTime.Add(time.Hour).Unix()
		claims["orig_iat"] = fixedTime.Unix()
		tokenString, _ := token.SignedString(key)

		w := performRequest(handler, "GET", "/auth/hello", "", map[string]string{
			"Authorization": "Bearer " + tokenString,
		}, nil)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("WithLeeway_AcceptsTokenWithNbfInNearFuture", func(t *testing.T) {
		authMiddleware, _ := New(&EchoJWTMiddleware{
			Realm:         "test zone",
			Key:           key,
			Timeout:       time.Hour,
			Authenticator: defaultAuthenticator,
			ParseOptions: []jwt.ParserOption{
				jwt.WithLeeway(60 * time.Second),
			},
			TimeFunc: func() time.Time {
				return fixedTime
			},
		})

		handler := echoHandler(authMiddleware)

		token := jwt.New(jwt.GetSigningMethod("HS256"))
		claims := token.Claims.(jwt.MapClaims)
		claims["identity"] = testAdmin
		claims["exp"] = fixedTime.Add(2 * time.Hour).Unix()
		claims["nbf"] = fixedTime.Add(30 * time.Second).Unix()
		claims["orig_iat"] = fixedTime.Unix()
		tokenString, _ := token.SignedString(key)

		w := performRequest(handler, "GET", "/auth/hello", "", map[string]string{
			"Authorization": "Bearer " + tokenString,
		}, nil)
		assert.Equal(t, http.StatusOK, w.Code)
		data := gjson.Get(w.Body.String(), "text")
		assert.Equal(t, "Hello World.", data.String())
	})

	t.Run("CombineLeewayWithOtherParseOptions", func(t *testing.T) {
		authMiddleware, _ := New(&EchoJWTMiddleware{
			Realm:         "test zone",
			Key:           key,
			Timeout:       time.Hour,
			Authenticator: defaultAuthenticator,
			ParseOptions: []jwt.ParserOption{
				jwt.WithLeeway(60 * time.Second),
				jwt.WithJSONNumber(),
			},
			TimeFunc: func() time.Time {
				return fixedTime.Add(time.Hour + 45*time.Second)
			},
		})

		handler := echoHandler(authMiddleware)

		token := jwt.New(jwt.GetSigningMethod("HS256"))
		claims := token.Claims.(jwt.MapClaims)
		claims["identity"] = testAdmin
		claims["exp"] = fixedTime.Add(time.Hour).Unix()
		claims["orig_iat"] = fixedTime.Unix()
		claims["user_id"] = 12345
		tokenString, _ := token.SignedString(key)

		w := performRequest(handler, "GET", "/auth/hello", "", map[string]string{
			"Authorization": "Bearer " + tokenString,
		}, nil)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}
