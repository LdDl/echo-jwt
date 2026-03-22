package jwt

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
	"github.com/tidwall/gjson"
)

// validAuthenticator is a properly functioning authenticator for cookie tests
var validAuthenticator = func(c *echo.Context) (any, error) {
	var loginVals Login
	if err := c.Bind(&loginVals); err != nil {
		return "", ErrMissingLoginValues
	}
	if loginVals.Username == testAdmin && loginVals.Password == testPassword {
		return loginVals.Username, nil
	}
	return "", ErrFailedAuthentication
}

func TestSetRefreshTokenCookie(t *testing.T) {
	mw, _ := New(&EchoJWTMiddleware{
		Realm:                  "test zone",
		Key:                    key,
		Timeout:                time.Hour,
		RefreshTokenTimeout:    24 * time.Hour,
		Authenticator:          validAuthenticator,
		SendCookie:             true,
		RefreshTokenCookieName: "refresh_token",
		CookieDomain:           "example.com",
		SecureCookie:           false,
		CookieHTTPOnly:         true,
		TimeFunc:               time.Now,
	})

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	c := e.NewContext(req, w)

	refreshToken := "test-refresh-token-12345"

	mw.SetRefreshTokenCookie(c, refreshToken)

	cookies := w.Result().Cookies()

	// Should have one refresh token cookie
	assert.Len(t, cookies, 1)
	assert.Equal(t, "refresh_token", cookies[0].Name)
	assert.Equal(t, refreshToken, cookies[0].Value)
	assert.Equal(t, "example.com", cookies[0].Domain)
	assert.True(t, cookies[0].HttpOnly)
	assert.True(t, cookies[0].Secure) // Refresh token cookies are always secure (HTTPS only)
	assert.Equal(t, "/", cookies[0].Path)
	assert.True(t, cookies[0].MaxAge > 0)
}

func TestSetRefreshTokenCookieDisabled(t *testing.T) {
	mw, _ := New(&EchoJWTMiddleware{
		Realm:               "test zone",
		Key:                 key,
		Timeout:             time.Hour,
		RefreshTokenTimeout: 24 * time.Hour,
		Authenticator:       validAuthenticator,
		SendCookie:          false, // Cookie disabled
		TimeFunc:            time.Now,
	})

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	c := e.NewContext(req, w)

	refreshToken := "test-refresh-token-12345"

	mw.SetRefreshTokenCookie(c, refreshToken)

	cookies := w.Result().Cookies()

	// Should not set any cookies when SendCookie is false
	assert.Len(t, cookies, 0)
}

func TestExtractRefreshTokenFromCookie(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:                  "test zone",
		Key:                    key,
		Timeout:                time.Hour,
		MaxRefresh:             time.Hour * 24,
		Authenticator:          validAuthenticator,
		SendCookie:             true,
		RefreshTokenCookieName: "refresh_token",
	})

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.AddCookie(&http.Cookie{
		Name:  "refresh_token",
		Value: "test-refresh-token-from-cookie",
	})
	w := httptest.NewRecorder()
	c := e.NewContext(req, w)

	// Test extraction
	token := authMiddleware.extractRefreshToken(c)
	assert.Equal(t, "test-refresh-token-from-cookie", token)
}

func TestExtractRefreshTokenPriority(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:                  "test zone",
		Key:                    key,
		Timeout:                time.Hour,
		MaxRefresh:             time.Hour * 24,
		Authenticator:          validAuthenticator,
		SendCookie:             true,
		RefreshTokenCookieName: "refresh_token",
	})

	// Test: Cookie has highest priority over form
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.AddCookie(&http.Cookie{
		Name:  "refresh_token",
		Value: "from-cookie",
	})
	req.Form = map[string][]string{
		"refresh_token": {"from-form"},
	}
	w := httptest.NewRecorder()
	c := e.NewContext(req, w)

	token := authMiddleware.extractRefreshToken(c)
	assert.Equal(t, "from-cookie", token, "Cookie should have highest priority")
}

func TestLoginHandlerSetsRefreshTokenCookie(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:                  "test zone",
		Key:                    key,
		Timeout:                time.Hour,
		RefreshTokenTimeout:    24 * time.Hour,
		MaxRefresh:             time.Hour * 24,
		Authenticator:          validAuthenticator,
		SendCookie:             true,
		CookieName:             "jwt",
		RefreshTokenCookieName: "refresh_token",
	})

	handler := echoHandler(authMiddleware)

	w := performRequest(handler, "POST", "/login",
		`{"username":"`+testAdmin+`","password":"`+testPassword+`"}`, nil, nil)

	assert.Equal(t, http.StatusOK, w.Code)

	// Check that both cookies are set
	setCookieHeaders := w.Result().Header.Values("Set-Cookie")
	assert.True(t, len(setCookieHeaders) >= 2, "Should set at least 2 cookies")

	hasJWTCookie := false
	hasRefreshTokenCookie := false

	for _, cookie := range setCookieHeaders {
		if contains(cookie, "jwt=") {
			hasJWTCookie = true
		}
		if contains(cookie, "refresh_token=") {
			hasRefreshTokenCookie = true
		}
	}

	assert.True(t, hasJWTCookie, "Should set JWT cookie")
	assert.True(t, hasRefreshTokenCookie, "Should set refresh token cookie")

	// Verify response contains tokens
	accessToken := gjson.Get(w.Body.String(), "access_token")
	refreshToken := gjson.Get(w.Body.String(), "refresh_token")
	assert.True(t, accessToken.Exists())
	assert.True(t, refreshToken.Exists())
}

func TestRefreshHandlerWithCookie(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:                  "test zone",
		Key:                    key,
		Timeout:                time.Hour,
		RefreshTokenTimeout:    24 * time.Hour,
		MaxRefresh:             time.Hour * 24,
		Authenticator:          validAuthenticator,
		SendCookie:             true,
		CookieName:             "jwt",
		RefreshTokenCookieName: "refresh_token",
	})

	handler := echoHandler(authMiddleware)

	// First, login to get refresh token
	w := performRequest(handler, "POST", "/login",
		`{"username":"`+testAdmin+`","password":"`+testPassword+`"}`, nil, nil)
	assert.Equal(t, http.StatusOK, w.Code)
	refreshToken := gjson.Get(w.Body.String(), "refresh_token").String()
	assert.NotEmpty(t, refreshToken)

	// Test refresh with cookie (automatic)
	w = performRequest(handler, "POST", "/refresh", "", nil, []*http.Cookie{
		{Name: "refresh_token", Value: refreshToken},
	})
	assert.Equal(t, http.StatusOK, w.Code)

	// Check that new tokens are returned
	newAccessToken := gjson.Get(w.Body.String(), "access_token")
	newRefreshToken := gjson.Get(w.Body.String(), "refresh_token")
	assert.True(t, newAccessToken.Exists())
	assert.True(t, newRefreshToken.Exists())
	assert.NotEqual(t, refreshToken, newRefreshToken.String(), "Refresh token should be rotated")

	// Check that new cookies are set
	setCookieHeaders := w.Result().Header.Values("Set-Cookie")
	assert.True(t, len(setCookieHeaders) >= 2, "Should set new cookies")
}

func TestRefreshHandlerWithoutCookie(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:               "test zone",
		Key:                 key,
		Timeout:             time.Hour,
		RefreshTokenTimeout: 24 * time.Hour,
		MaxRefresh:          time.Hour * 24,
		Authenticator:       validAuthenticator,
		SendCookie:          true,
		CookieName:          "jwt",
	})

	handler := echoHandler(authMiddleware)

	// First, login to get refresh token
	w := performRequest(handler, "POST", "/login",
		`{"username":"`+testAdmin+`","password":"`+testPassword+`"}`, nil, nil)
	assert.Equal(t, http.StatusOK, w.Code)
	refreshToken := gjson.Get(w.Body.String(), "refresh_token").String()
	assert.NotEmpty(t, refreshToken)

	// Test refresh with form data (manual)
	req := httptest.NewRequest("POST", "/refresh",
		strings.NewReader("refresh_token="+refreshToken))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	newAccessToken := gjson.Get(w.Body.String(), "access_token")
	assert.True(t, newAccessToken.Exists())

	// Test refresh with JSON body
	w = performRequest(handler, "POST", "/login",
		`{"username":"`+testAdmin+`","password":"`+testPassword+`"}`, nil, nil)
	refreshToken2 := gjson.Get(w.Body.String(), "refresh_token").String()

	w = performRequest(handler, "POST", "/refresh",
		`{"refresh_token":"`+refreshToken2+`"}`, nil, nil)
	assert.Equal(t, http.StatusOK, w.Code)

	newAccessToken = gjson.Get(w.Body.String(), "access_token")
	assert.True(t, newAccessToken.Exists())
}

func TestLogoutHandlerClearsRefreshTokenCookie(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:                  "test zone",
		Key:                    key,
		Timeout:                time.Hour,
		RefreshTokenTimeout:    24 * time.Hour,
		MaxRefresh:             time.Hour * 24,
		Authenticator:          validAuthenticator,
		SendCookie:             true,
		CookieName:             "jwt",
		RefreshTokenCookieName: "refresh_token",
	})

	handler := echoHandler(authMiddleware)

	// First, login to get tokens
	w := performRequest(handler, "POST", "/login",
		`{"username":"`+testAdmin+`","password":"`+testPassword+`"}`, nil, nil)
	assert.Equal(t, http.StatusOK, w.Code)
	accessToken := gjson.Get(w.Body.String(), "access_token").String()
	refreshToken := gjson.Get(w.Body.String(), "refresh_token").String()
	assert.NotEmpty(t, accessToken)
	assert.NotEmpty(t, refreshToken)

	// Logout with cookies
	w = performRequest(handler, "POST", "/logout", "", map[string]string{
		"Authorization": "Bearer " + accessToken,
	}, []*http.Cookie{
		{Name: "jwt", Value: accessToken},
		{Name: "refresh_token", Value: refreshToken},
	})
	assert.Equal(t, http.StatusOK, w.Code)

	// Check that both cookies are cleared (MaxAge=-1)
	setCookieHeaders := w.Result().Header.Values("Set-Cookie")
	assert.True(t, len(setCookieHeaders) >= 2, "Should clear cookies")

	hasJWTClear := false
	hasRefreshTokenClear := false

	for _, cookie := range setCookieHeaders {
		if contains(cookie, "jwt=") && contains(cookie, "Max-Age=0") {
			hasJWTClear = true
		}
		if contains(cookie, "refresh_token=") && contains(cookie, "Max-Age=0") {
			hasRefreshTokenClear = true
		}
	}

	assert.True(t, hasJWTClear, "Should clear JWT cookie")
	assert.True(t, hasRefreshTokenClear, "Should clear refresh token cookie")
}

func TestRefreshTokenRevocationOnLogout(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:               "test zone",
		Key:                 key,
		Timeout:             time.Hour,
		RefreshTokenTimeout: 24 * time.Hour,
		MaxRefresh:          time.Hour * 24,
		Authenticator:       validAuthenticator,
	})

	handler := echoHandler(authMiddleware)

	// Login to get tokens
	w := performRequest(handler, "POST", "/login",
		`{"username":"`+testAdmin+`","password":"`+testPassword+`"}`, nil, nil)
	assert.Equal(t, http.StatusOK, w.Code)
	accessToken := gjson.Get(w.Body.String(), "access_token").String()
	refreshToken := gjson.Get(w.Body.String(), "refresh_token").String()

	// Logout to revoke refresh token
	req := httptest.NewRequest("POST", "/logout",
		strings.NewReader("refresh_token="+refreshToken))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Try to use revoked refresh token
	req = httptest.NewRequest("POST", "/refresh",
		strings.NewReader("refresh_token="+refreshToken))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRefreshTokenCookieName(t *testing.T) {
	customCookieName := "my_refresh_token"

	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:                  "test zone",
		Key:                    key,
		Timeout:                time.Hour,
		RefreshTokenTimeout:    24 * time.Hour,
		MaxRefresh:             time.Hour * 24,
		Authenticator:          validAuthenticator,
		SendCookie:             true,
		RefreshTokenCookieName: customCookieName,
	})

	// Check default is set correctly during init
	assert.Equal(t, customCookieName, authMiddleware.RefreshTokenCookieName)

	handler := echoHandler(authMiddleware)

	// Login and check custom cookie name
	w := performRequest(handler, "POST", "/login",
		`{"username":"`+testAdmin+`","password":"`+testPassword+`"}`, nil, nil)
	assert.Equal(t, http.StatusOK, w.Code)

	setCookieHeaders := w.Result().Header.Values("Set-Cookie")
	hasCustomCookie := false

	for _, cookie := range setCookieHeaders {
		if contains(cookie, customCookieName+"=") {
			hasCustomCookie = true
			break
		}
	}

	assert.True(t, hasCustomCookie, "Should use custom refresh token cookie name")
}

func TestRefreshTokenCookieDefault(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:               "test zone",
		Key:                 key,
		Timeout:             time.Hour,
		RefreshTokenTimeout: 24 * time.Hour,
		MaxRefresh:          time.Hour * 24,
		Authenticator:       validAuthenticator,
		SendCookie:          true,
		// Don't set RefreshTokenCookieName to test default
	})

	// Check default is set during init
	assert.Equal(t, "refresh_token", authMiddleware.RefreshTokenCookieName)
}

func TestTokenGeneratorSetsRefreshToken(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:               "test zone",
		Key:                 key,
		Timeout:             time.Hour,
		RefreshTokenTimeout: 24 * time.Hour,
		Authenticator:       validAuthenticator,
	})

	ctx := context.Background()
	userData := testAdmin

	tokenPair, err := authMiddleware.TokenGenerator(ctx, userData)

	assert.NoError(t, err)
	assert.NotNil(t, tokenPair)
	assert.NotEmpty(t, tokenPair.AccessToken)
	assert.NotEmpty(t, tokenPair.RefreshToken)
	assert.Equal(t, "Bearer", tokenPair.TokenType)
	assert.True(t, tokenPair.ExpiresAt > 0)
	assert.True(t, tokenPair.CreatedAt > 0)
}

func TestExtractRefreshTokenContentType(t *testing.T) {
	authMiddleware, _ := New(&EchoJWTMiddleware{
		Realm:                  "test zone",
		Key:                    key,
		Timeout:                time.Hour,
		RefreshTokenCookieName: "refresh_token",
	})

	e := echo.New()

	t.Run("JSON body with application/json Content-Type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test",
			strings.NewReader(`{"refresh_token":"from-json-body"}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		c := e.NewContext(req, w)
		_ = c

		token := authMiddleware.extractRefreshToken(c)
		assert.Equal(t, "from-json-body", token,
			"Should extract from JSON body with application/json Content-Type")
	})

	t.Run("Form body with application/x-www-form-urlencoded Content-Type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test",
			strings.NewReader("refresh_token=from-form-body"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		c := e.NewContext(req, w)

		token := authMiddleware.extractRefreshToken(c)
		assert.Equal(t, "from-form-body", token,
			"Should extract from form body with application/x-www-form-urlencoded Content-Type")
	})

	t.Run("Query parameters are not supported (security)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test?refresh_token=from-query",
			strings.NewReader(`{"refresh_token":"from-json-body"}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		c := e.NewContext(req, w)

		token := authMiddleware.extractRefreshToken(c)
		assert.Equal(t, "from-json-body", token,
			"Query parameter should be ignored for security, JSON body should be used")
	})

	t.Run("Cookie takes highest precedence over body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test",
			strings.NewReader(`{"refresh_token":"from-json-body"}`))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{
			Name:  "refresh_token",
			Value: "from-cookie",
		})
		w := httptest.NewRecorder()
		c := e.NewContext(req, w)

		token := authMiddleware.extractRefreshToken(c)
		assert.Equal(t, "from-cookie", token, "Cookie should have highest precedence")
	})
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
