package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/cristalhq/jwt/v5"
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
	tokenContextKey       contextKey = "token"
	userIDContextKey      contextKey = "userID"
	companyIDContextKey   contextKey = "companyID"
	permissionsContextKey contextKey = "permissions"
)

// TokenClaims contains data from the claims in a JWT token.
type TokenClaims struct {
	jwt.RegisteredClaims
	CompanyID   string   `json:"companyID"`
	Permissions []string `json:"permissions"`
}

// validator is a function which can be given to Auth middleware function to ensure some claim
// is checked for validity
type validator func(claims TokenClaims) bool

// ValidatePermissions is a validator function which compares a set of provided permissions for a
// given resource against the permissions contained in the Permissions claim of a JWT token.
func ValidatePermissions(resourcePermissions ...string) validator {
	return func(claims TokenClaims) bool {
		for _, rPerm := range resourcePermissions {
			if !slices.Contains(claims.Permissions, rPerm) {
				return false
			}
		}
		return true
	}
}

// ValidateUserID is a validator function that compares the provided userID with the Subject claim of a JWT
// token.
func ValidateUserID(userID string) validator {
	return func(claims TokenClaims) bool {
		return claims.Subject == userID
	}
}

// ValidateUserID is a validator function that compares the provided userID with the CompanyID claim of a JWT
// token.
func ValidateCompanyID(companyID string) validator {
	return func(claims TokenClaims) bool {
		return claims.CompanyID == companyID
	}
}

// ValidateNotExpired is a validator function that checks if the token's expiry time has passed.
func ValidateNotExpired() validator {
	return func(claims TokenClaims) bool {
		return time.Now().After(claims.ExpiresAt.Time)
	}
}

func tokenFromHeader(header http.Header) (string, error) {
	authorization := header.Get(headerAuthorization)
	if len(authorization) < 7 && authorization[0:6] != bearerPrefix {
		return "", errAuthBearerNotProvided
	}
	return authorization[7:], nil
}

/*
	Implementation written for Go's stdlib.
*/

// Auth is a middleware function which retrieves a JWT token from header,
// parses it and validates it's signature. This function can optionally apply our own validation logic
// (ie. to check token claims).
func Auth(next http.Handler, validators ...validator) http.Handler {
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

		var claims TokenClaims
		if err := json.Unmarshal(token.Claims(), &claims); err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		// apply authentication functions to validate token based on your custom rules.
		if validators != nil {
			for _, validator := range validators {
				if !validator(claims) {
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

// Verify extracts a JWT token from an Authorization Bearer header and verifies the singature.
// Verify will then load the token into the request context for further usage down the middleware
// stack.
func Verify(next http.Handler, verifier jwt.Verifier) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		encodedToken, err := tokenFromHeader(r.Header)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		tokenStr, err := base64.StdEncoding.DecodeString(encodedToken)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		token, err := jwt.Parse([]byte(tokenStr), verifier)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), tokenContextKey, token)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ProcessClaims retrieves the claims we're interested in from the token and adds them to the
// request's context for further use later on in the middleware stack.
func ProcessClaims(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, _ := r.Context().Value(tokenContextKey).(*jwt.Token) // verified by upstream middleware

		var claims TokenClaims
		if err := json.Unmarshal(token.Claims(), &claims); err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), userIDContextKey, claims.Subject)
		ctx = context.WithValue(ctx, companyIDContextKey, claims.CompanyID)
		ctx = context.WithValue(ctx, permissionsContextKey, claims.Permissions)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// WithPermissions checks the provided permissions for a protected resource against the permissions
// provided by the user token's claims. If the optional boolean AllowSelf is set to true, this check is skipped.
func WithPermissions(next http.Handler, allowSelf bool, resourcePermissions ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userPermissions, ok := r.Context().Value(permissionsContextKey).([]string)
		if !ok {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		if allowSelf {
			// handle getting userID from somewhere
		}

		for _, rPerm := range resourcePermissions {
			if !slices.Contains(userPermissions, rPerm) {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

/*
	Implementation written for chi router.
*/

// ChiAuth is a middleware function which retrieves a JWT token from header,
// parses it and validates it's signature. This function can optionally apply our own validation logic
// (ie. to check token claims).
//
// This middleware is designed to be used in chi router.
func ChiAuth(validators ...validator) func(http.Handler) http.Handler {
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

			var claims TokenClaims
			if err := json.Unmarshal(token.Claims(), &claims); err != nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			if validators != nil {
				for _, validator := range validators {
					if !validator(claims) {
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

// ChiVerify extracts a JWT token from an Authorization Bearer header and verifies the singature.
// ChiVerify will then load the token into the request context for further usage down the middleware
// stack.
//
// This middleware is designed to be used in chi router.
func ChiVerify(verifier jwt.Verifier) func(http.Handler) http.Handler {
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
			// Load token into request context for further use.
			ctx := context.WithValue(r.Context(), tokenContextKey, token)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(fn)
	}
}

// ProcessClaims retrieves the claims we're interested in from the token and adds them to the
// request's context for further use later on in the middleware stack.
//
// This middleware is designed to be used in chi router.
func ChiProcessClaims() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			token, ok := r.Context().Value(tokenContextKey).(*jwt.Token)
			if !ok {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			var claims TokenClaims
			if err := json.Unmarshal(token.Claims(), &claims); err != nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

		}
		return http.HandlerFunc(fn)
	}
}

// ChiWithPermissions checks the provided permissions for a protected resource against the permissions
// provided by the user token's claims. If the optional boolean AllowSelf is set to true, this check is skipped.
//
// This middleware is designed to be used in chi router.
func ChiWithPermissions(resourcePermissions ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			token, ok := r.Context().Value(tokenContextKey).(*jwt.Token)
			if !ok {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			var claims TokenClaims
			if err := json.Unmarshal(token.Claims(), &claims); err != nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			for _, resourcePermission := range resourcePermissions {
				if !slices.Contains(claims.Permissions, resourcePermission) {
					http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
					return
				}
			}

			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}
