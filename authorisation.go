// main.go
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/oauth2"
)

// Configuration - replace with your provider values or use env vars.
var (
	clientID     = os.Getenv("OAUTH_CLIENT_ID")     // required
	clientSecret = os.Getenv("OAUTH_CLIENT_SECRET") // required
	redirectURL  = os.Getenv("OAUTH_REDIRECT_URL")  // e.g. http://localhost:8080/callback
	authURL      = os.Getenv("OAUTH_AUTH_URL")      // provider authorize endpoint
	tokenURL     = os.Getenv("OAUTH_TOKEN_URL")     // provider token endpoint
	scope        = os.Getenv("OAUTH_SCOPE")         // e.g. "openid profile email"
	// resourceURL is an example protected resource to call after auth (optional)
	resourceURL = os.Getenv("OAUTH_RESOURCE_URL") // e.g. https://provider.example.com/userinfo
)

// oauthConfig is the oauth2.Config used for the auth code flow.
var oauthConfig *oauth2.Config

// stateCookieName is the name of the cookie used to store the state.
const stateCookieName = "oauth_state"

// randomState generates a cryptographically secure random string for state.
func randomState(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// writeJSON helper
func writeJSON(w http.ResponseWriter, v interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// loginHandler redirects the user to the provider's authorization page.
func loginHandler(w http.ResponseWriter, r *http.Request) {
	// create state and store it in a secure (HttpOnly) cookie
	state, err := randomState(16)
	if err != nil {
		http.Error(w, "failed to create state", http.StatusInternalServerError)
		return
	}

	// set cookie with same-site lax, HttpOnly; short expiry
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil, // if using HTTPS this should be true
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(10 * time.Minute),
	})

	// Generate the URL to redirect the user to.
	authCodeURL := oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline) // AccessTypeOffline requests refresh token if provider supports it
	http.Redirect(w, r, authCodeURL, http.StatusFound)
}

// callbackHandler validates state and exchanges code for token.
func callbackHandler(w http.ResponseWriter, r *http.Request) {
	// read state cookie
	cookie, err := r.Cookie(stateCookieName)
	if err != nil {
		http.Error(w, "state cookie missing", http.StatusBadRequest)
		return
	}
	expectedState := cookie.Value

	// read state and code from query params
	query := r.URL.Query()
	state := query.Get("state")
	code := query.Get("code")
	if state == "" || code == "" {
		http.Error(w, "missing state or code in callback", http.StatusBadRequest)
		return
	}

	// validate state
	if state != expectedState {
		http.Error(w, "invalid state parameter", http.StatusBadRequest)
		return
	}

	// Exchange the code for a token
	ctx := context.Background()
	token, err := oauthConfig.Exchange(ctx, code)
	if err != nil {
		msg := fmt.Sprintf("token exchange failed: %v", err)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}

	// store token in a secure cookie for demo purposes (NOT recommended for production)
	// better: store in server-side session or database, encrypted, associated with the user.
	tokenJSON, _ := json.Marshal(token)
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_token",
		Value:    base64.URLEncoding.EncodeToString(tokenJSON),
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(24 * time.Hour),
	})

	// Respond with a simple message and link to profile
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<h2>Authentication successful ✅</h2>
<p>You can now visit <a href="/profile">/profile</a> to call a protected resource.</p>`)
}

// readTokenFromCookie decodes token from cookie (demo only).
func readTokenFromCookie(r *http.Request) (*oauth2.Token, error) {
	c, err := r.Cookie("oauth_token")
	if err != nil {
		return nil, err
	}
	decoded, err := base64.URLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil, err
	}
	var token oauth2.Token
	if err := json.Unmarshal(decoded, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

// profileHandler makes an authenticated request to resourceURL (or shows token info).
func profileHandler(w http.ResponseWriter, r *http.Request) {
	// retrieve token
	token, err := readTokenFromCookie(r)
	if err != nil {
		http.Error(w, "no token found; please /login first", http.StatusUnauthorized)
		return
	}

	// create a token source that will automatically refresh if necessary
	ctx := context.Background()
	ts := oauthConfig.TokenSource(ctx, token)

	// fetch a valid token (refreshes if needed)
	validToken, err := ts.Token()
	if err != nil {
		http.Error(w, "failed to get valid token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// If resourceURL provided, call it.
	if resourceURL != "" {
		client := oauth2.NewClient(ctx, ts)
		resp, err := client.Get(resourceURL)
		if err != nil {
			http.Error(w, "error calling resource: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			// proxy the body to user
			w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
			w.WriteHeader(resp.StatusCode)
			_, _ = http.MaxBytesReader(w, resp.Body, 1<<20).WriteTo(w) // up to 1MB
			return
		}
		http.Error(w, "resource returned status "+resp.Status, resp.StatusCode)
		return
	}

	// Otherwise show token details (for demo)
	writeJSON(w, map[string]interface{}{
		"access_token":  validToken.AccessToken,
		"token_type":    validToken.TokenType,
		"expiry":        validToken.Expiry,
		"refresh_token": validToken.RefreshToken,
	}, http.StatusOK)
}

// logoutHandler clears cookies (demo only).
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// expire cookies
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Unix(0, 0),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Unix(0, 0),
	})
	fmt.Fprintln(w, "Logged out (cookies cleared).")
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintln(w, "ok")
}

func main() {
	// Basic env validation
	if clientID == "" || clientSecret == "" || redirectURL == "" || authURL == "" || tokenURL == "" {
		log.Println("Missing configuration: you must set OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, OAUTH_REDIRECT_URL, OAUTH_AUTH_URL, OAUTH_TOKEN_URL")
		log.Println("Optional: OAUTH_SCOPE, OAUTH_RESOURCE_URL")
		// For safety, exit with helpful message
		// If you prefer inline values, replace the variables above instead of env vars.
		os.Exit(1)
	}

	// Build oauth config
	oauthConfig = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
	}

	// parse scope if provided (space-separated)
	if scope != "" {
		oauthConfig.Scopes = append(oauthConfig.Scopes, splitScope(scope)...)
	}

	// HTTP routes
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<h1>Go OAuth2 Authorization Code Demo 🔐</h1>
<ul>
<li><a href="/login">/login</a> - start auth flow</li>
<li><a href="/profile">/profile</a> - call protected resource (requires login)</li>
<li><a href="/logout">/logout</a> - clear demo cookies</li>
</ul>`)
	})
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/callback", callbackHandler)
	http.HandleFunc("/profile", profileHandler)
	http.HandleFunc("/logout", logoutHandler)

	addr := ":8080"
	log.Printf("Starting server at %s — visit http://localhost%s/login to begin\n", addr, addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

// splitScope splits a space-separated scope string into a slice.
func splitScope(s string) []string {
	var out []string
	current := ""
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' {
			if current != "" {
				out = append(out, current)
				current = ""
			}
			continue
		}
		current += string(c)
	}
	if current != "" {
		out = append(out, current)
	}
	return out
}
