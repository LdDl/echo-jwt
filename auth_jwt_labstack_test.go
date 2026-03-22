package jwt

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for labstack echo-jwt features: Skipper, BeforeFunc, SuccessHandler,
// ErrorHandler, ContinueOnIgnoredError, typed errors.

func TestTokenParsingError(t *testing.T) {
	inner := errors.New("parsing error")
	err := &TokenParsingError{Err: inner}

	assert.Equal(t, "parsing error", err.Error())
	assert.Equal(t, inner, err.Unwrap())
	assert.True(t, errors.Is(err, inner))
}

func TestTokenExtractionError(t *testing.T) {
	inner := errors.New("extraction error")
	err := &TokenExtractionError{Err: inner}

	assert.Equal(t, "extraction error", err.Error())
	assert.Equal(t, inner, err.Unwrap())
	assert.True(t, errors.Is(err, inner))
}

func TestSkipper(t *testing.T) {
	authMiddleware, err := New(&EchoJWTMiddleware{
		Realm:         "test zone",
		Key:           []byte("secret key"),
		Authenticator: defaultAuthenticator,
		Skipper: func(c *echo.Context) bool {
			return c.Request().URL.Path == "/public"
		},
	})
	require.NoError(t, err)

	handler := echoHandler(authMiddleware)

	// Public path should be accessible without token
	r := performRequest(handler, "GET", "/public", "", nil, nil)
	assert.NotEqual(t, http.StatusUnauthorized, r.Code, "public path should not require auth")

	// Protected path should require token
	r = performRequest(handler, "GET", "/auth/hello", "", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, r.Code, "protected path should require auth")
}

func TestBeforeFunc(t *testing.T) {
	beforeCalled := false

	authMiddleware, err := New(&EchoJWTMiddleware{
		Realm:         "test zone",
		Key:           []byte("secret key"),
		Authenticator: defaultAuthenticator,
		BeforeFunc: func(c *echo.Context) {
			beforeCalled = true
		},
	})
	require.NoError(t, err)

	handler := echoHandler(authMiddleware)

	// Make a request (will fail auth, but BeforeFunc should still be called)
	performRequest(handler, "GET", "/auth/hello", "", nil, nil)
	assert.True(t, beforeCalled, "BeforeFunc should be called before token extraction")
}

func TestBeforeFuncNotCalledWhenSkipped(t *testing.T) {
	beforeCalled := false

	authMiddleware, err := New(&EchoJWTMiddleware{
		Realm:         "test zone",
		Key:           []byte("secret key"),
		Authenticator: defaultAuthenticator,
		Skipper: func(c *echo.Context) bool {
			return true // skip everything
		},
		BeforeFunc: func(c *echo.Context) {
			beforeCalled = true
		},
	})
	require.NoError(t, err)

	handler := echoHandler(authMiddleware)
	performRequest(handler, "GET", "/auth/hello", "", nil, nil)
	assert.False(t, beforeCalled, "BeforeFunc should not be called when Skipper returns true")
}

func TestSuccessHandler(t *testing.T) {
	successCalled := false

	authMiddleware, err := New(&EchoJWTMiddleware{
		Realm: "test zone",
		Key:   []byte("secret key"),
		Authenticator: func(c *echo.Context) (interface{}, error) {
			var loginVals Login
			if err := c.Bind(&loginVals); err != nil {
				return "", ErrMissingLoginValues
			}
			if loginVals.Username == "admin" && loginVals.Password == "admin" {
				return loginVals.Username, nil
			}
			return "", ErrFailedAuthentication
		},
		SuccessHandler: func(c *echo.Context) error {
			successCalled = true
			return nil
		},
	})
	require.NoError(t, err)

	handler := echoHandler(authMiddleware)

	// Login first to get token
	r := performRequest(
		handler,
		"POST",
		"/login",
		`{"username":"admin","password":"admin"}`,
		map[string]string{"Content-Type": "application/json"},
		nil,
	)
	require.Equal(t, http.StatusOK, r.Code)
	token := getTokenFromResponse(t, r)

	// Use the token - SuccessHandler should be called
	successCalled = false
	r = performRequest(
		handler,
		"GET",
		"/auth/hello",
		"",
		map[string]string{"Authorization": "Bearer " + token},
		nil,
	)
	assert.Equal(t, http.StatusOK, r.Code)
	assert.True(t, successCalled, "SuccessHandler should be called on valid token")
}

func TestSuccessHandlerError(t *testing.T) {
	customErr := errors.New("success handler rejected")

	authMiddleware, err := New(&EchoJWTMiddleware{
		Realm: "test zone",
		Key:   []byte("secret key"),
		Authenticator: func(c *echo.Context) (interface{}, error) {
			var loginVals Login
			if err := c.Bind(&loginVals); err != nil {
				return "", ErrMissingLoginValues
			}
			if loginVals.Username == "admin" && loginVals.Password == "admin" {
				return loginVals.Username, nil
			}
			return "", ErrFailedAuthentication
		},
		SuccessHandler: func(c *echo.Context) error {
			return customErr
		},
	})
	require.NoError(t, err)

	handler := echoHandler(authMiddleware)

	// Login to get token
	r := performRequest(
		handler,
		"POST",
		"/login",
		`{"username":"admin","password":"admin"}`,
		map[string]string{"Content-Type": "application/json"},
		nil,
	)
	require.Equal(t, http.StatusOK, r.Code)
	token := getTokenFromResponse(t, r)

	// SuccessHandler returns error - request should fail
	r = performRequest(
		handler,
		"GET",
		"/auth/hello",
		"",
		map[string]string{"Authorization": "Bearer " + token},
		nil,
	)
	// Echo returns 500 for unhandled errors from middleware
	assert.NotEqual(t, http.StatusOK, r.Code, "SuccessHandler error should stop the chain")
}

func TestErrorHandler(t *testing.T) {
	errorHandlerCalled := false
	var receivedErr error

	authMiddleware, err := New(&EchoJWTMiddleware{
		Realm:         "test zone",
		Key:           []byte("secret key"),
		Authenticator: defaultAuthenticator,
		ErrorHandler: func(c *echo.Context, err error) error {
			errorHandlerCalled = true
			receivedErr = err
			return echo.NewHTTPError(http.StatusForbidden, "custom error")
		},
	})
	require.NoError(t, err)

	handler := echoHandler(authMiddleware)

	// Request without token should trigger ErrorHandler
	r := performRequest(handler, "GET", "/auth/hello", "", nil, nil)
	assert.True(t, errorHandlerCalled, "ErrorHandler should be called on auth failure")
	assert.NotNil(t, receivedErr, "ErrorHandler should receive an error")

	// Check that the error is a typed error
	var parsingErr *TokenParsingError
	var extractionErr *TokenExtractionError
	isTyped := errors.As(receivedErr, &parsingErr) || errors.As(receivedErr, &extractionErr)
	assert.True(t, isTyped, "ErrorHandler should receive a typed error (TokenParsingError or TokenExtractionError)")

	assert.Equal(t, http.StatusForbidden, r.Code, "should use ErrorHandler's response code")
}

func TestErrorHandlerWithInvalidToken(t *testing.T) {
	var receivedErr error

	authMiddleware, err := New(&EchoJWTMiddleware{
		Realm:         "test zone",
		Key:           []byte("secret key"),
		Authenticator: defaultAuthenticator,
		ErrorHandler: func(c *echo.Context, err error) error {
			receivedErr = err
			return echo.NewHTTPError(http.StatusUnauthorized, "bad token")
		},
	})
	require.NoError(t, err)

	handler := echoHandler(authMiddleware)

	// Request with invalid token
	r := performRequest(
		handler,
		"GET",
		"/auth/hello",
		"",
		map[string]string{"Authorization": "Bearer invalid.token.here"},
		nil,
	)
	assert.Equal(t, http.StatusUnauthorized, r.Code)

	// Should be a TokenParsingError (token was extracted but failed to parse)
	var parsingErr *TokenParsingError
	assert.True(t, errors.As(receivedErr, &parsingErr), "invalid token should produce TokenParsingError")
}

func TestContinueOnIgnoredError(t *testing.T) {
	authMiddleware, err := New(&EchoJWTMiddleware{
		Realm:                  "test zone",
		Key:                    []byte("secret key"),
		Authenticator:          defaultAuthenticator,
		ContinueOnIgnoredError: true,
		ErrorHandler: func(c *echo.Context, err error) error {
			// Set a default public identity
			c.Set("public_user", true)
			return nil // ignore the error
		},
	})
	require.NoError(t, err)

	e := echo.New()
	e.POST("/login", authMiddleware.LoginHandler)
	auth := e.Group("/auth")
	auth.Use(authMiddleware.MiddlewareFunc())
	auth.GET("/hello", func(c *echo.Context) error {
		isPublic := c.Get("public_user")
		if isPublic != nil {
			return c.JSON(http.StatusOK, map[string]interface{}{
				"message": "public access",
				"public":  true,
			})
		}
		return c.JSON(http.StatusOK, map[string]interface{}{
			"message": "authenticated access",
			"public":  false,
		})
	})

	// Request without token - should continue to handler as public user
	r := performRequest(e, "GET", "/auth/hello", "", nil, nil)
	assert.Equal(t, http.StatusOK, r.Code, "should continue when ErrorHandler returns nil")
	assert.Contains(t, r.Body.String(), "public access")
}

func TestContinueOnIgnoredErrorFalse(t *testing.T) {
	authMiddleware, err := New(&EchoJWTMiddleware{
		Realm:                  "test zone",
		Key:                    []byte("secret key"),
		Authenticator:          defaultAuthenticator,
		ContinueOnIgnoredError: false, // default
		ErrorHandler: func(c *echo.Context, err error) error {
			return nil // ignore the error
		},
	})
	require.NoError(t, err)

	handler := echoHandler(authMiddleware)

	// ErrorHandler returns nil but ContinueOnIgnoredError is false
	// Should stop the chain (return nil = no error, no response)
	r := performRequest(handler, "GET", "/auth/hello", "", nil, nil)
	// The handler chain is stopped, no JSON body from the hello handler
	assert.NotContains(t, r.Body.String(), "Hello World")
}

func TestSkipperWithLogin(t *testing.T) {
	authMiddleware, err := New(&EchoJWTMiddleware{
		Realm:         "test zone",
		Key:           []byte("secret key"),
		Authenticator: defaultAuthenticator,
		Skipper: func(c *echo.Context) bool {
			// Skip middleware only for specific paths
			return strings.HasPrefix(c.Request().URL.Path, "/public")
		},
	})
	require.NoError(t, err)

	e := echo.New()
	e.POST("/login", authMiddleware.LoginHandler)
	e.GET("/public/info", func(c *echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{"public": true})
	})
	auth := e.Group("/auth")
	auth.Use(authMiddleware.MiddlewareFunc())
	auth.GET("/hello", helloHandler)

	// Public route works without auth
	r := performRequest(e, "GET", "/public/info", "", nil, nil)
	assert.Equal(t, http.StatusOK, r.Code)
	assert.Contains(t, r.Body.String(), "public")

	// Auth route still requires token
	r = performRequest(e, "GET", "/auth/hello", "", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, r.Code)
}

// Helper to extract access_token from login response
func getTokenFromResponse(t *testing.T, r *httptest.ResponseRecorder) string {
	t.Helper()
	body := r.Body.String()
	// Simple extraction - find access_token in JSON
	idx := strings.Index(body, `"access_token":"`)
	if idx == -1 {
		t.Fatalf("no access_token in response: %s", body)
	}
	start := idx + len(`"access_token":"`)
	end := strings.Index(body[start:], `"`)
	if end == -1 {
		t.Fatalf("malformed access_token in response: %s", body)
	}
	return body[start : start+end]
}
