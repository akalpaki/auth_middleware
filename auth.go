package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"

	"github.com/cristalhq/jwt/v5"
	"github.com/go-chi/chi/v5"
)

const (
	headerAuthorization = "Authorization"
	bearerPrefix        = "Bearer "
)

var (
	errAuthBearerNotProvided = errors.New("authentication header does not have \"Bearer x\" format")
)

var (
	secretKey []byte
	verifier  *jwt.HSAlg
)

func init() {
	var err error
	secretKey = []byte(os.Getenv("JWT_SECRET_KEY"))
	verifier, err = jwt.NewVerifierHS(jwt.HS256, secretKey)
	if err != nil {
		panic("Invalid key or signing algorithm!!!")
	}
}

type contextKey string

const (
	tokenContextKey contextKey = "token"
)

type MyToken struct {
	jwt.RegisteredClaims
	Permissions string `json:"permissions"`
}

func tokenFromHeader(header http.Header) (string, error) {
	authorization := header.Get(headerAuthorization)
	if len(authorization) < 7 && authorization[0:6] != bearerPrefix {
		return "", errAuthBearerNotProvided
	}
	return authorization[7:], nil
}

type authFunc func(claims MyToken) bool

// IsAuthenticated is a middleware function which retrieves a JWT token from header,
// parses it and validates it's signature. This function can optionally apply our own validation logic
// (ie. to check token claims).
func IsAuthenticated(next http.Handler, authFunc ...authFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		encodedToken, err := tokenFromHeader(r.Header)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		tokenStr, err := base64.StdEncoding.Strict().DecodeString(encodedToken)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		token, err := jwt.Parse([]byte(tokenStr), verifier)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		var tokenClaims MyToken
		if err := json.Unmarshal(token.Claims(), &tokenClaims); err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		// apply authentication functions to validate token based on your custom rules.
		if authFunc != nil {
			for _, f := range authFunc {
				if !f(tokenClaims) {
					http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
					return
				}
			}

		}
		// Load token into request context for further use.
		ctx := context.WithValue(r.Context(), tokenContextKey, token)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func ChiAuth(authFuncs ...authFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			encodedToken, err := tokenFromHeader(r.Header)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			tokenStr, err := base64.StdEncoding.Strict().DecodeString(encodedToken)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			token, err := jwt.Parse([]byte(tokenStr), verifier)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			var tokenClaims MyToken
			if err := json.Unmarshal(token.Claims(), &tokenClaims); err != nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			// apply authentication functions to validate token based on your custom rules.
			if authFunc != nil {
				for _, f := range authFunc {
					if !f(tokenClaims) {
						http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
						return
					}
				}

			}
			// Load token into request context for further use.
			ctx := context.WithValue(r.Context(), tokenContextKey, token)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(fn)
	}
}

func Route() {
	r := chi.NewRouter()
	r.With(ChiAuth(WithCompanyID, WithPermissions()...))
}
