package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	jwt "github.com/LdDl/echo-jwt"
	"github.com/LdDl/echo-jwt/core"
	"github.com/labstack/echo/v5"
	gojwt "github.com/golang-jwt/jwt/v5"
	_ "github.com/joho/godotenv/autoload"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

const identityKey = "id"

var (
	port              string
	googleOauthConfig *oauth2.Config
	githubOauthConfig *oauth2.Config
	// Store OAuth state tokens to prevent CSRF attacks
	oauthStateStore = make(map[string]time.Time)
)

// User represents the user information from OAuth provider
type User struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	Provider  string `json:"provider"`
	AvatarURL string `json:"avatar_url,omitempty"`
}

// GoogleUserInfo represents Google user information
type GoogleUserInfo struct {
	ID      string `json:"id"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
}

// GitHubUserInfo represents GitHub user information
type GitHubUserInfo struct {
	ID        int    `json:"id"`
	Login     string `json:"login"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
}

func init() {
	port = os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	// Google OAuth2 Configuration
	googleOauthConfig = &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  fmt.Sprintf("http://localhost:%s/auth/google/callback", port),
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	// GitHub OAuth2 Configuration
	githubOauthConfig = &oauth2.Config{
		ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		RedirectURL:  fmt.Sprintf("http://localhost:%s/auth/github/callback", port),
		Scopes:       []string{"user:email"},
		Endpoint:     github.Endpoint,
	}

	// Clean up expired state tokens every 10 minutes
	go cleanupExpiredStates()
}

func main() {
	// Validate OAuth configuration
	if googleOauthConfig.ClientID == "" && githubOauthConfig.ClientID == "" {
		log.Println(
			"Warning: No OAuth providers configured. Set GOOGLE_CLIENT_ID/SECRET or GITHUB_CLIENT_ID/SECRET",
		)
	}

	e := echo.New()

	// Initialize JWT middleware
	authMiddleware, err := jwt.New(initJWTParams())
	if err != nil {
		log.Fatal("JWT Error:" + err.Error())
	}

	if err := authMiddleware.MiddlewareInit(); err != nil {
		log.Fatal("authMiddleware.MiddlewareInit() Error:" + err.Error())
	}

	// Register routes
	registerRoute(e, authMiddleware)

	// Start HTTP server
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           e,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("Server starting on http://localhost:%s", port)
	log.Printf("Demo Page: http://localhost:%s/demo", port)
	log.Println("\nOAuth Login URLs:")
	if googleOauthConfig.ClientID != "" {
		log.Printf("  Google: http://localhost:%s/auth/google/login", port)
	}
	if githubOauthConfig.ClientID != "" {
		log.Printf("  GitHub: http://localhost:%s/auth/github/login", port)
	}
	if googleOauthConfig.ClientID == "" && githubOauthConfig.ClientID == "" {
		log.Println("  (No OAuth providers configured)")
	}

	if err = srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func registerRoute(e *echo.Echo, handle *jwt.EchoJWTMiddleware) {
	// Enable CORS for development
	e.Use(corsMiddleware())

	// Public routes
	e.GET("/", indexHandler)
	e.File("/demo", "./index.html")

	// OAuth login initiation
	e.GET("/auth/google/login", handleGoogleLogin)
	e.GET("/auth/github/login", handleGitHubLogin)

	// OAuth callbacks
	e.GET("/auth/google/callback", handleGoogleCallback(handle))
	e.GET("/auth/github/callback", handleGitHubCallback(handle))

	// JWT token refresh
	e.POST("/auth/refresh", handle.RefreshHandler)

	// Protected routes
	auth := e.Group("/api")
	auth.Use(handle.MiddlewareFunc())
	auth.GET("/profile", profileHandler)
	auth.POST("/logout", handle.LogoutHandler)
}

func initJWTParams() *jwt.EchoJWTMiddleware {
	return &jwt.EchoJWTMiddleware{
		Realm:       "oauth-sso-zone",
		Key:         []byte(getSecretKey()),
		Timeout:     time.Hour,
		MaxRefresh:  time.Hour * 24,
		IdentityKey: identityKey,
		PayloadFunc: payloadFunc(),

		IdentityHandler: identityHandler(),
		Authenticator:   authenticator(),
		Authorizer:      authorizer(),
		Unauthorized:    unauthorized(),
		LogoutResponse:  logoutResponse(),
		TokenLookup:     "header: Authorization, query: token, cookie: jwt",
		TokenHeadName:   "Bearer",
		TimeFunc:        time.Now,

		// Enable built-in cookie support for better security
		SendCookie:        true,
		SecureCookie:      false, // Set to true in production with HTTPS
		CookieHTTPOnly:    true,
		CookieMaxAge:      time.Hour,
		CookieDomain:      "",
		SendAuthorization: true, // Send Authorization header in LoginResponse

		// Custom LoginResponse to handle OAuth redirect vs regular JSON response
		LoginResponse: func(c *echo.Context, token *core.Token) {
			provider := c.Get("oauth_provider")
			if provider != nil {
				// OAuth: redirect to demo page (token already set in cookie by echo-jwt)
				redirectURL := fmt.Sprintf("/demo?provider=%s", provider)
				c.Redirect(http.StatusFound, redirectURL)
				return
			}

			// Regular login: return JSON response
			c.JSON(http.StatusOK, map[string]interface{}{
				"code":          http.StatusOK,
				"access_token":  token.AccessToken,
				"token_type":    token.TokenType,
				"refresh_token": token.RefreshToken,
				"expires_at":    token.ExpiresAt,
			})
		},
	}
}

func getSecretKey() string {
	key := os.Getenv("JWT_SECRET_KEY")
	if key == "" {
		key = "default-secret-key-change-in-production"
	}
	return key
}

func payloadFunc() func(data any) gojwt.MapClaims {
	return func(data any) gojwt.MapClaims {
		if v, ok := data.(*User); ok {
			return gojwt.MapClaims{
				identityKey: v.ID,
				"email":     v.Email,
				"name":      v.Name,
				"provider":  v.Provider,
				"avatar":    v.AvatarURL,
			}
		}
		return gojwt.MapClaims{}
	}
}

func identityHandler() func(c *echo.Context) any {
	return func(c *echo.Context) any {
		claims := jwt.ExtractClaims(c)
		return &User{
			ID:        claims[identityKey].(string),
			Email:     getStringFromClaims(claims, "email"),
			Name:      getStringFromClaims(claims, "name"),
			Provider:  getStringFromClaims(claims, "provider"),
			AvatarURL: getStringFromClaims(claims, "avatar"),
		}
	}
}

func authenticator() func(c *echo.Context) (any, error) {
	return func(c *echo.Context) (any, error) {
		// This is not used for OAuth flow, but required by the middleware
		// OAuth authentication happens in the callback handlers
		return nil, jwt.ErrMissingLoginValues
	}
}

func authorizer() func(c *echo.Context, data any) bool {
	return func(c *echo.Context, data any) bool {
		// All authenticated OAuth users are authorized
		if _, ok := data.(*User); ok {
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
		claims := jwt.ExtractClaims(c)
		c.JSON(http.StatusOK, map[string]interface{}{
			"code":    http.StatusOK,
			"message": "Successfully logged out",
			"user":    claims["email"],
		})
	}
}

// handleOAuthSuccess handles the successful OAuth authentication
// and uses echo-jwt's built-in features (SendCookie, LoginResponse, etc.)
func handleOAuthSuccess(
	c *echo.Context,
	authMiddleware *jwt.EchoJWTMiddleware,
	user *User,
	provider string,
) error {
	// Set user identity in context (for middleware callbacks)
	c.Set(authMiddleware.IdentityKey, user)
	c.Set("oauth_provider", provider)

	// Generate JWT token
	token, err := authMiddleware.TokenGenerator(c.Request().Context(), user)
	if err != nil {
		return err
	}

	// Set cookies (both access token and refresh token)
	authMiddleware.SetCookie(c, token.AccessToken)
	authMiddleware.SetRefreshTokenCookie(c, token.RefreshToken)

	// Let echo-jwt handle everything (cookies, headers, response) via LoginResponse
	// The middleware will automatically:
	// - Set httpOnly cookie (if SendCookie is enabled)
	// - Set Authorization header (if SendAuthorization is enabled)
	// - Call LoginResponse callback (defined in initJWTParams)
	if authMiddleware.LoginResponse != nil {
		authMiddleware.LoginResponse(c, token)
	}

	return nil
}

// OAuth handlers
func handleGoogleLogin(c *echo.Context) error {
	if googleOauthConfig.ClientID == "" {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"error": "Google OAuth not configured"})
	}

	state := generateStateToken()
	url := googleOauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)
	return c.Redirect(http.StatusTemporaryRedirect, url)
}

func handleGitHubLogin(c *echo.Context) error {
	if githubOauthConfig.ClientID == "" {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"error": "GitHub OAuth not configured"})
	}

	state := generateStateToken()
	url := githubOauthConfig.AuthCodeURL(state)
	return c.Redirect(http.StatusTemporaryRedirect, url)
}

func handleGoogleCallback(authMiddleware *jwt.EchoJWTMiddleware) echo.HandlerFunc {
	return func(c *echo.Context) error {
		// Validate state token (CSRF protection)
		state := c.QueryParam("state")
		if !validateStateToken(state) {
			return c.JSON(http.StatusBadRequest, map[string]interface{}{"error": "Invalid state token"})
		}

		// Exchange authorization code for access token
		code := c.QueryParam("code")
		token, err := googleOauthConfig.Exchange(context.Background(), code)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]interface{}{"error": "Failed to exchange token"})
		}

		// Get user info from Google
		client := googleOauthConfig.Client(context.Background(), token)
		resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]interface{}{"error": "Failed to get user info"})
		}
		defer resp.Body.Close()

		data, _ := io.ReadAll(resp.Body)
		var googleUser GoogleUserInfo
		if err := json.Unmarshal(data, &googleUser); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]interface{}{"error": "Failed to parse user info"})
		}

		// Create user object
		user := &User{
			ID:        "google_" + googleUser.ID,
			Email:     googleUser.Email,
			Name:      googleUser.Name,
			Provider:  "google",
			AvatarURL: googleUser.Picture,
		}

		// Handle OAuth success with proper JWT middleware integration
		if err := handleOAuthSuccess(c, authMiddleware, user, "google"); err != nil {
			return c.JSON(
				http.StatusInternalServerError,
				map[string]interface{}{"error": "Failed to complete authentication"},
			)
		}
		return nil
	}
}

func handleGitHubCallback(authMiddleware *jwt.EchoJWTMiddleware) echo.HandlerFunc {
	return func(c *echo.Context) error {
		// Validate state token (CSRF protection)
		state := c.QueryParam("state")
		if !validateStateToken(state) {
			return c.JSON(http.StatusBadRequest, map[string]interface{}{"error": "Invalid state token"})
		}

		// Exchange authorization code for access token
		code := c.QueryParam("code")
		token, err := githubOauthConfig.Exchange(context.Background(), code)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]interface{}{"error": "Failed to exchange token"})
		}

		// Get user info from GitHub
		client := githubOauthConfig.Client(context.Background(), token)
		resp, err := client.Get("https://api.github.com/user")
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]interface{}{"error": "Failed to get user info"})
		}
		defer resp.Body.Close()

		data, _ := io.ReadAll(resp.Body)
		var githubUser GitHubUserInfo
		if err := json.Unmarshal(data, &githubUser); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]interface{}{"error": "Failed to parse user info"})
		}

		// Get user email if not public
		email := githubUser.Email
		if email == "" {
			email = getUserEmail(client)
		}

		// Create user object
		user := &User{
			ID:        fmt.Sprintf("github_%d", githubUser.ID),
			Email:     email,
			Name:      githubUser.Name,
			Provider:  "github",
			AvatarURL: githubUser.AvatarURL,
		}

		// Handle OAuth success with proper JWT middleware integration
		if err := handleOAuthSuccess(c, authMiddleware, user, "github"); err != nil {
			return c.JSON(
				http.StatusInternalServerError,
				map[string]interface{}{"error": "Failed to complete authentication"},
			)
		}
		return nil
	}
}

// Helper functions
func generateStateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	oauthStateStore[state] = time.Now().Add(10 * time.Minute)
	return state
}

func validateStateToken(state string) bool {
	expiry, exists := oauthStateStore[state]
	if !exists {
		return false
	}
	if time.Now().After(expiry) {
		delete(oauthStateStore, state)
		return false
	}
	delete(oauthStateStore, state)
	return true
}

func cleanupExpiredStates() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		for state, expiry := range oauthStateStore {
			if now.After(expiry) {
				delete(oauthStateStore, state)
			}
		}
	}
}

func getUserEmail(client *http.Client) string {
	resp, err := client.Get("https://api.github.com/user/emails")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	var emails []struct {
		Email   string `json:"email"`
		Primary bool   `json:"primary"`
	}

	data, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(data, &emails); err != nil {
		return ""
	}

	for _, email := range emails {
		if email.Primary {
			return email.Email
		}
	}

	if len(emails) > 0 {
		return emails[0].Email
	}

	return ""
}

func getStringFromClaims(claims gojwt.MapClaims, key string) string {
	if val, ok := claims[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

// CORS middleware for development
func corsMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			c.Response().Header().Set("Access-Control-Allow-Origin", "*")
			c.Response().Header().Set("Access-Control-Allow-Credentials", "true")
			c.Response().Header().
				Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
			c.Response().Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

			if c.Request().Method == "OPTIONS" {
				return c.NoContent(204)
			}

			return next(c)
		}
	}
}

// Route handlers
func indexHandler(c *echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "OAuth SSO Example with echo-jwt",
		"endpoints": map[string]interface{}{
			"demo_page":     "/demo",
			"google_login":  "/auth/google/login",
			"github_login":  "/auth/github/login",
			"profile":       "/api/profile (requires JWT)",
			"refresh_token": "/auth/refresh (requires JWT)",
			"logout":        "/api/logout (requires JWT)",
		},
	})
}

func profileHandler(c *echo.Context) error {
	claims := jwt.ExtractClaims(c)
	user := c.Get(identityKey)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"code": http.StatusOK,
		"user": user,
		"claims": map[string]interface{}{
			"id":       claims[identityKey],
			"email":    claims["email"],
			"name":     claims["name"],
			"provider": claims["provider"],
			"avatar":   claims["avatar"],
			"exp":      claims["exp"],
			"iat":      claims["iat"],
		},
	})
}
